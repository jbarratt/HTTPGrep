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
use List::Util qw(shuffle);
use Time::Interval;
use Carp::Always;
use Data::Dumper;
use Net::CIDR;
use Socket;
use Digest::MD5 qw(md5_hex);

use Moose;
use namespace::autoclean;

with 'MooseX::SimpleConfig';
with 'MooseX::Getopt';
with 'MooseX::LazyLogDispatch';

has '+configfile' => (default => '/etc/httpgrep.yml');

# set in config file or on CLI
has 'urifile'     => (is => 'ro', isa => 'Str'); 
has 'oneuri'      => (is => 'ro', isa => 'Str');
has 'debug'       => (is => 'ro', isa => 'Bool', default => 0);
has 'rescan_time' => (is => 'ro', isa => 'Int', default => 86400);
has 'user_agent'  => (is => 'ro', isa => 'Str', required => 1);
has 'max_active'  => (is => 'ro', isa => 'Int', default => 20);
has 'rec_per_c'   => (is => 'ro', isa => 'Int', default => 2_000);
has 'search_pat'  => (is => 'ro', isa => 'HashRef', required => 1);
has 'cidr_map'    => (is => 'ro', isa => 'HashRef', required => 1);
has 'finalizeonly' => (is => 'ro', isa => 'Bool', default => 0);
has 'debug'       => (is => 'ro', isa => 'Bool', default => 0);

# internal
has 'urimap'      => (is => 'rw', isa => 'HashRef', default => sub { {} });
has 'r'           => (is => 'rw', isa => 'Redis', lazy_build => 1);
has 'cores'       => (is => 'ro', isa => 'Int', default => sub { Sys::CPU::cpu_count(); });
has 'pm'          => (is => 'rw', isa => 'Parallel::ForkManager');
has 'parser'      => (is => 'ro', isa => 'HTML::Parser', lazy_build => 1);
has 'rec_procd'   => (is => 'rw', isa => 'Int', default => 0);
has 'oneuri_procd'    => (is => 'rw', isa => 'Bool', default => 0);
has 'oneuri_scanned'    => (is => 'rw', isa => 'HashRef', default => sub { {} });
has 'configfile_md5'   => (is => 'rw', isa => 'Str');

has log_dispatch_conf => (
    is => 'ro', isa => 'HashRef', lazy => 1, required => 1,
    default => sub {
        my $self = shift;
        return ($self->debug || $self->oneuri)
            ? {
                class => 'Log::Dispatch::Screen',
                min_level => 'debug',
                stderr => 1,
                format => '[%p] %m at %F line %L%n', 
            }
            : {
                class => 'Log::Dispatch::Syslog',
                min_level => 'info',
                facility => 'daemon',
                ident => 'httpgrep',
                format => '[%p] %m',
            };
    },
);

=method run
    The main 'run' process (to be called by the daemon, not reporting tools.)
    Launches one process per core, then generates the reporting information
=cut

sub run {
    my($self) = @_;
    if($self->finalizeonly) {
        $self->finalize_scan();
    } elsif($self->oneuri) {
        # just run the scan for this one URI (for testing)
        # shouldn't touch redis at all and/or interrupt a 'real' running scan
        $self->logger->info("scanning in --oneuri mode (" . $self->oneuri . ")");
        $self->pm(Parallel::ForkManager->new(1));
        if($self->pm->start) {
            $self->pm->wait_all_children;
            exit;
        } else {
            $self->scanning_child();
        }
    } else {
        # Run the full scan in normal mode
        $self->logger->info("launching a full scan");
        $self->pm(Parallel::ForkManager->new($self->cores));
       
        $self->initialize_scan();
        while(1) {
            my $q = $self->queue_size;
            last unless $q;
            last if $self->config_modified;
            $self->logger->debug("Queue: $q. Completion estimated in " . $self->completion_estimate . ", running for " . $self->run_time);
            $self->pm->start && next;
            $self->scanning_child();
            $self->pm->finish; # should never get hit.
        }
        $self->logger->info("Queue empty. Waiting for all children to complete processing");
        $self->pm->wait_all_children;
        $self->logger->info("Children complete. Finalizing scan.");
        $self->finalize_scan();
        $self->logger->info("Scan Complete");
    } 
}

=method queue_size
    Returns the count of the queue size, including some nice recoonnect logic if needed.
=cut

sub queue_size {
    my($self) = @_;
    #eval { 
    #    if(!$self->r->ping) { $self->reconnect_redis(); }; 
    #};
    $self->reconnect_redis();
    return $self->r->llen('uri_queue');
}

=method scanning_child
    This method is what a forked child process runs. It actually dequeues work, scans, and parses.
=cut

sub scanning_child {
    my($self) = @_;
    
    if(!$self->oneuri) {
        $self->reconnect_redis();
    }

    my $t; $t = AnyEvent->timer(
        after    => 1,
        interval => 1,
        cb       => sub {
            while($AnyEvent::HTTP::ACTIVE < $self->{max_active}) {
                #my $uri = $self->r->lpop('uri_queue');
                my $uri = $self->dequeue_uri();
                last unless defined($uri);
                last unless $self->process_another(1);
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
            } elsif(!$self->process_another) {
               $self->logger->debug("Child [$$] hit max requests; $AnyEvent::HTTP::ACTIVE requests outstanding."); 
            }

            if($self->config_modified) {
                $self->logger->info("Config Modified. Finishing up active work and quitting.");
                # fake being at max requests so we exit
                $self->rec_procd($self->rec_per_c);
            }
        },
    );

    AnyEvent->condvar->recv;
}

sub process_another {
    my($self, $inc) = @_;
    my $p = $self->rec_procd;
    if($p > $self->rec_per_c) {
        return 0;
    } elsif($inc) {
        $self->rec_procd($p+$inc);
    }
    return 1;
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
            $self->classify_uri("$name", $arg{uri});
        }
    }
    if($arg{depth} <= 1) {
        my $uri = URI->new($arg{uri});
        $self->parser->handler(
            start => 
                sub { my($t, $a) = @_;
                    if($a->{'src'} || $a->{'href'}) {
                        my $dest_uri = URI->new_abs($a->{src} || $a->{href}, $uri);
                        if(!$self->already_scanned($dest_uri->as_string)) {
                            http_request
                                GET => $dest_uri->as_string,
                                timeout => 15,
                                sub {
                                    my ($body, $hdr) = @_;
                                    if($hdr->{Status} =~ /^2/) {
                                        $self->scan_content(uri => $dest_uri->as_string, body => $body, depth => ($arg{depth}+1));
                                    }
                            };
                            #$self->r->sadd('scanned_scripts', $dest_uri->as_string);
                            $self->mark_scanned($dest_uri->as_string);
                        }
                    }
               },
        "tagname, attr");
        $self->parser->parse($arg{'body'});
    }
}

=method dequeue_uri
    Returns next uri in the processing queue (or virtual queue if we are in 'oneuri' mode
=cut

sub dequeue_uri {
    my ($self) = @_;
    if($self->oneuri) {
        if($self->oneuri_procd) {
            return undef;
        } else {
            $self->oneuri_procd(1);
            return $self->oneuri;
        }
    } else {
        return $self->r->lpop('uri_queue');
    }
}

=method mark_scanned
    Mark that we have scanned a URI. This stops us from loading the same resource over and over (e.g. google jquery)
=cut

sub mark_scanned {
    my ($self, $uri) = @_;
    if($self->oneuri) {
        $self->oneuri_scanned->{$uri}++;
    } else {
        $self->r->sadd('scanned_scripts', $uri);
    }
}

=method already_scanned 
    Checks if we've already seen a page as being scanned
=cut

sub already_scanned {
    my ($self, $uri) = @_;
    if($self->oneuri) {
        return defined($self->oneuri_scanned->{$uri});
    } else {
        return $self->r->sismember('scanned_scripts', $uri)
    }
}

=method initialize_scan
    Prepares the system to launch a new scan. Does cleanup/accounting in redis.
    Loads the uris from $self->urimap
=cut

sub initialize_scan {
    my($self) = @_;

    if($self->queue_size <= 0) {
        $self->logger->info("Queue empty. Reloading and resetting live_match");
        $self->r->del('uri_queue');
        # clean up all the live_match buckets
        for my $search (keys %{$self->search_pat}) {
            for my $class ($self->r->smembers("ptr_classifications")) {
                $self->logger->debug("Flushing the queue live_match:$search:$class");
                $self->r->del("live_match:$search:$class");
            }
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
    } else {
        $self->logger->info("Queue not empty, resuming processing");
    }
    # optionally flush the list of 'script uris we have already processed'
    # want to periodically flush to keep track of new patterns.
    my $last_scanned_reset = $self->r->get('last_scanned_reset') || 0;
    if((time - $last_scanned_reset) > $self->rescan_time) {
        $self->r->del('scanned_scripts');
        $self->r->set('last_scanned_reset', time);
    }
    
    $self->r->set('scan_start', time());
    $self->r->set('scan_size', $self->r->llen('uri_queue'));
}

=method classify_uri
    Classify a URI, doing the lookups asynchronously.
=cut

sub classify_uri {
    my($self, $type, $uri) = @_;
    my $domain = URI->new($uri)->host;
    
    AnyEvent::DNS::a $domain,
        sub {
            my $ip = shift;
            if(!$ip) {
                $self->logger->info("Unable to do a DNS lookup for $domain");
                return;
            }
            my $class = "Other";
            for my $block (keys %{$self->cidr_map}) {
                $self->logger->debug("Checking if IP $ip is a member of block $block");
                if(Net::CIDR::cidrlookup($ip, ($block))) {
                    $class = $self->cidr_map->{$block};
                    last;
                }
            }
            my $key = $self->find_domain_key($domain);
            $self->logger->info("Matched $type in $uri (Key: $key, Classification: $class)");
            if(!$self->oneuri) {
                $self->r->sadd("live_match:$type:$class", "$key,$domain,$uri");
                $self->r->sadd('ptr_classifications', $class);
            }
        };
}

=method finalize_scan
    After a scan is complete, copy 'live_match' to 'last_match'
=cut

sub finalize_scan {
    my($self) = @_;
    
    # store any values from this scan
    for my $search (keys %{$self->search_pat}) {
        # clean these out. We'll go repopulate with current values
        for my $class ($self->r->smembers("ptr_classifications")) {
            $self->r->del("last_match:$search:$class");
            
            # equivalent of a copy
            $self->r->sunionstore("last_match:$search:$class", "live_match:$search:$class");

            # merge these results into all those we have ever seen
            $self->r->sunionstore("all_matches", "all_matches", "last_match:$search:$class");
        }
    }
}

=method get_results
    Return raw results. 
    'search=>' and 'class=>' can both optionally be provided to filter results.
=cut

sub get_results {
    my($self, %arg) = @_;
    my @results = ();
    for my $search (keys %{$self->search_pat}) {
        next if ($arg{'search'} && $arg{'search'} ne $search);
        for my $class ($self->r->smembers("ptr_classifications")) {
            next if ($arg{'class'} && $arg{'class'} ne $class);
            push(@results, $self->r->sunion("live_match:$search:$class", "last_match:$search:$class"));
        }
    }
    return @results;
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
    return "Other";
}

=method completion_estimate
    Return a human readable guess about how long it'll be until this pass is complete
=cut

sub completion_estimate {
    my($self) = @_;
    my $now = time;
    my $now_size = $self->r->llen('uri_queue') || 0;
    my $orig_size = $self->r->get('scan_size');
    my $launch_ts = $self->r->get('scan_start');

    if($now == $launch_ts) { return " [TBD] "; }

    # simple projection, we have done X per second, so how many seconds until done?
    my $uri_per_sec = ($orig_size-$now_size)/($now-$launch_ts);
    if($uri_per_sec == 0) { return " [TBD] "; } 
    return parseInterval(seconds => int($now_size/$uri_per_sec), String => 1);
}

=method run_time
    Human readable form of how long this scan has been running.
=cut

sub run_time {
    my($self) = @_;
    my $now = time;
    my $launch_ts = $self->r->get('scan_start');

    return parseInterval(seconds => int($now-$launch_ts), String => 1);
}

=method config_modified
    Returns 1 if the md5sum of the config file has changed since creating the object
=cut

sub config_modified {
    my ($self) = @_;
    my $md5 = $self->get_configfile_md5();
    if($md5 eq $self->configfile_md5) {
        return 0;
    } else {
        $self->logger->debug("configfile checksum changed from " . $self->configfile_md5 . " to $md5");
        return 1;
    }
}

=method get_configfile_md5
    returns the md5sum of the configfile
=cut

sub get_configfile_md5 {
    my ($self) = @_;
    open(my $fh, "<", $self->configfile);
    my $contents = do { local $/ = <$fh> };
    return md5_hex($contents);
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

    # set the configfile md5 so we can check against it later
    $self->configfile_md5($self->get_configfile_md5);
}

sub _build_r {
    return Redis->new();
}

sub _build_parser {
    my $parser = HTML::Parser->new( api_version => 3);
    $parser->report_tags(qw(script)); # add in 'a' to recurse a level deeper
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
