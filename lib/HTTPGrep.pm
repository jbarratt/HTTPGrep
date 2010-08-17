use strict;
use warnings;
package HTTPGrep;

# ABSTRACT: A high performance HTTP scanner built on AnyEvent::HTTP and Redis

use AnyEvent::HTTP;
use Redis;
use HTML::Parser;
use YAML qw(LoadFile);
use URI;
use Time::HiRes qw(time);
use Sys::CPU;
use Getopt::Long;
use Parallel::ForkManager;
use Net::ADNS qw(ADNS_R_A ADNS_R_PTR);
use List::Util qw(shuffle);
use Time::Interval;

use Moose;
use namespace::autoclean;

with 'MooseX::SimpleConfig';
with 'MooseX::Getopt';

has '+configfile' => (default => '/etc/httpgrep.yml');

# set in config file or on CLI
has 'urifile'     => (is => 'ro', isa => 'Str'); 
has 'debug'       => (is => 'ro', isa => 'Bool', default => 0);
has 'rescan_time' => (is => 'ro', isa => 'Int', default => 86400);
has 'user_agent'  => (is => 'ro', isa => 'Str', required => 1);
has 'max_active'  => (is => 'ro', isa => 'Int', default => 20);
has 'search_pat'  => (is => 'ro', isa => 'HashRef', required => 1);
has 'ptr_pat'     => (is => 'ro', isa => 'HashRef', required => 1);

# internal
has 'urimap'      => (is => 'rw', isa => 'HashRef', default => sub { {} });
has 'r'           => (is => 'rw', isa => 'Redis', lazy_build => 1);
has 'cores'       => (is => 'ro', isa => 'Int', default => sub { Sys::CPU::cpu_count(); });
has 'pm'          => (is => 'rw', isa => 'Parallel::ForkManager');
has 'parser'      => (is => 'ro', isa => 'HTML::Parser', lazy_build => 1);

=method run
    The main 'run' process (to be called by the daemon, not reporting tools.)
    Launches one process per core, then generates the reporting information
=cut

sub run {
    my($self) = @_;
    $self->pm(Parallel::ForkManager->new($self->cores));
    $self->initialize_scan();
    for (1 .. $self->cores) {
        $self->pm->start && next;
        $self->scanning_child();
        $self->pm->finish; # should never get hit.
    }
    $self->pm->wait_all_children;
    $self->finalize_scan();
}

=method scanning_child
    This method is what a forked child process runs. It actually dequeues work, scans, and parses.
=cut

sub scanning_child {
    my($self) = @_;

    $self->reconnect_redis();

    my $t; $t = AnyEvent->timer(
        after    => 1,
        interval => 1,
        cb       => sub {
            while($AnyEvent::HTTP::ACTIVE < $self->{max_active}) {
                my $uri = $self->r->lpop('uri_queue');
                last unless defined($uri);
                http_request
                    GET => $uri,
                    timeout => 15,
                    sub {
                        my ($body, $hdr) = @_;
                        if($hdr->{Status} =~ /^2/) {
                            $self->scan_content(uri => $uri, body => $body, depth => 1);
                        }
                    };
            }
        },
    );

    my $done; $done = AnyEvent->timer(
        after    => 15,
        interval => 5,
        cb       => sub {
            if($AnyEvent::HTTP::ACTIVE == 0) {
                $self->pm->finish; # don't exit(1), our parent will forget about us.
            }
        },
    );

    AnyEvent->condvar->recv;
}

=method scan_content
    called by scanning_child when content is returned by AnyEvent::HTTP
=cut

sub scan_content {
    my ($self, %arg) = @_;
    return unless defined($arg{body}); #huh, empty body?
    
    for my $name (keys %{$self->search_pat}) {
        my $pat = $self->search_pat->{$name};
        if($arg{body} =~ /$pat/) {
            $self->r->sadd("live_match:$name", $arg{uri});
        }
    }
    if($arg{depth} <= 1) {
        my $uri = URI->new($arg{uri});
        $self->parser->handler(
            start => 
                sub { my($t, $a) = @_;
                    if($a->{'src'}) {
                        my $dest_uri = URI->new_abs($a->{src}, $uri);
                        if(!$self->r->sismember('scanned_scripts', $dest_uri->as_string)) {
                            http_request
                                GET => $dest_uri->as_string,
                                timeout => 15,
                                sub {
                                    my ($body, $hdr) = @_;
                                    if($hdr->{Status} =~ /^2/) {
                                        $self->scan_content(uri => $dest_uri->as_string, body => $body, depth => ($arg{depth}+1));
                                    }
                            };
                            $self->r->sadd('scanned_scripts', $dest_uri->as_string);
                        }
                    }
               },
        "tagname, attr");
        $self->parser->parse($arg{'body'});
    }
}

=method initialize_scan
    Prepares the system to launch a new scan. Does cleanup/accounting in redis.
    Loads the uris from $self->urimap
=cut

sub initialize_scan {
    my($self) = @_;

    # start with an empty list
    $self->r->del('uri_queue');

    # optionally flush the list of 'script uris we have already processed'
    # want to periodically flush to keep track of new patterns.
    my $last_scanned_reset = $self->r->get('last_scanned_reset') || 0;
    if((time - $last_scanned_reset) > $self->rescan_time) {
        $self->r->del('scanned_scripts');
        $self->r->set('last_scanned_reset', time);
    }
    
    # don't want to scan the sites in sequential order, randomize the domain list
    # (sequential == overloading 1 hostserver @ a time)
    for my $d (shuffle(keys %{$self->urimap})) {
        if($d !~ /^http/) {
            $self->r->rpush('uri_queue', "http://$d");
        } else {
            $self->r->rpush('uri_queue', $d);
        }
    }
    $self->r->set('scan_start', time());
    $self->r->set('scan_size', $self->r->llen('uri_queue'));
}

=method finalize_scan
    After a scan is complete, does PTR lookups on all domains and classifies them as per your regexes
=cut

sub finalize_scan {
    my($self) = @_;
    
    my $adns = Net::ADNS->new();
    $self->reconnect_redis();

    # store any values from this scan
    for my $search (keys %{$self->search_pat}) {
        $self->r->del("last_match:$search");
        # equivalent of a copy
        $self->r->sunionstore("last_match:$search", "live_match:$search");
        # merge these results into all those we have ever seen
        $self->r->sunionstore("all_matches", "all_matches", "last_match:$search");
        
        for my $uri ($self->r->smembers("last_match:$search")) {
            my $domain = URI->new($uri)->host;
            my $q = $adns->submit($domain, ADNS_R_A);
            $q->{match_uri} = $uri;
            $q->{match_type} = $search;
            $q->{orig_domain} = $domain;
        }
        # clean these out. We'll go repopulate with current values
        for my $class ($self->r->smembers("ptr_classifications")) {
            $self->r->del("last_match:$search:$class");
        }
    }
   
    my %classifications = (); 
    while(my $query = $adns->open_queries()) {        
        my $a = $adns->check($query);
        next unless defined($a);
        if(defined($a->{records}[0])) {
            if($a->{records}[0] =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
                my $q = $adns->submit("$4.$3.$2.$1.in-addr.arpa", ADNS_R_PTR);
                $q->{orig_domain} = $a->{orig_domain};
                $q->{match_type} = $a->{match_type};
                $q->{match_uri} = $a->{match_uri};
            } elsif ($a->{type} eq "PTR") {
                my $key = $self->find_domain_key($a->{orig_domain});
        
                my $class = $self->find_classification($a->{records}[0]);
                $classifications{$class}++;
                $self->r->sadd("last_match:$a->{match_type}:$class", "$key,$a->{orig_domain},$a->{match_uri},$a->{records}[0]"); 
            }
        }
    }
    $self->r->del('ptr_classifications');
    for my $k (keys %classifications) {
        $self->r->sadd('ptr_classifications', $k);
    }
}

=method find_classification
    Given a domain, figure out which classification you'd give it
    Processes the defined classes in ptr_pat hash
=cut

sub find_classification {
    my($self, $c) = @_;
    for my $name (keys %{$self->ptr_pat}) {
        my $pat = $self->ptr_pat->{$name};
        if($c =~ /$pat/) {
            return "$name-$1";
        }
    }
    return "NO_CLASS";
}

=method find_domain_key
    Given a domain, figure out which (if any) of the initial keys you passed in
    it can be mapped to
=cut

sub find_domain_key {
    my($self, $domain) = @_;
    my $key = undef;
    my @tokens = split(/\./, $domain);
    while(@tokens) {
        $key = $self->urimap->{join('.', @tokens)};
        return $key if $key;
        shift(@tokens);
    }
    return "NO_KEY";
}

=method completion_estimate
    Return a human readable guess about how long it'll be until this pass is complete
=cut

sub completion_estimate {
    my($self) = @_;
    my $now = time;
    my $now_size = $self->r->llen('uri_queue');
    my $orig_size = $self->r->get('scan_size');
    my $launch_ts = $self->r->get('scan_start');

    # simple projection, we have done X per second, so how many seconds until done?
    my $uri_per_sec = ($orig_size-$now_size)/($now-$launch_ts);
    return parseInterval(seconds => int($now_size/$uri_per_sec), String => 1);
}

sub BUILD {
    my ($self) = @_;
    # in some forms of this module's existence we won't need this
    if($self->urifile) {
        open(my $fh, "<", $self->urifile);
        while(<$fh>) {
            chomp;
            my($key, $uri) = split(/,/);
            $self->urimap->{$uri} = $key;
        }
    }
    $AnyEvent::HTTP::USERAGENT = $self->{user_agent};
}

sub _build_r {
    return Redis->new();
}

sub _build_parser {
    my $parser = HTML::Parser->new( api_version => 3);
    $parser->report_tags(qw(script));
    return $parser;
}
sub reconnect_redis {
   my($self) = @_;
   # don't really care if this fails...
   eval { $self->r->quit; };
   $self->r(Redis->new());
}

__PACKAGE__->meta->make_immutable;
1;
