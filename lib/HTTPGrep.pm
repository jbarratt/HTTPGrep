use strict;
use warnings;
package HTTPGrep;

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
has 'urifile'     => (is => 'ro', isa => 'Str'); 
has 'urimap'      => (is => 'rw', isa => 'HashRef', default => sub { {} });
has 'debug'       => (is => 'ro', isa => 'Bool', default => 0);
has 'user_agent'  => (is => 'ro', isa => 'Str', required => 1);
has 'max_active'  => (is => 'ro', isa => 'Int', default => 20);
has 'search_pat'  => (is => 'ro', isa => 'HashRef', required => 1);
has 'ptr_pat'     => (is => 'ro', isa => 'HashRef', required => 1);
has 'r'           => (is => 'rw', isa => 'Redis', lazy_build => 1);
has 'cores'       => (is => 'ro', isa => 'Int', default => sub { Sys::CPU::cpu_count(); });
has 'pm'          => (is => 'ro', isa => 'Parallel::ForkManager');


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
}

sub run {
    my($self) = @_;
    $self->pm(Parallel::ForkManager->new($self->cores));
    $self->initialize_scan();
    for (1 .. $cores) {
        $self->pm->start && next;
        $self->scanning_child();
        $self->pm->finish; # should never get hit.
    }
    $pm->wait_all_children;
    $self->finalize_scan();
}

sub scanning_child {
    my($self) = @_;
}

sub initialize_scan {
    my($self) = @_;

    # start with an empty list
    $self->r->del('uri_queue');
    
    # don't want to scan the sites in sequential order, randomize the domain list
    # (sequential == overloading 1 hostserver @ a time)
    for my $d (shuffle(keys %{$self->urimap})) {
        if($d !~ /^http/) {
            $pr->rpush('uri_queue', "http://$d");
        } else {
            $pr->rpush('uri_queue', $d);
        }
    }
    $self->r->set('scan_start', time());
    $self->r->set('scan_size', $self->r->llen('uri_queue'));
}


sub finalize_scan {
    my($self) = @_;
    
    # store any values from this scan
    for my $search (keys %{$self->search_pat}) {
        $self->r->del("last_match:$search");
        # equivalent of a copy
        $self->r->sunionstore("last_match:$search", "live_match:$search");
        # merge these results into all those we have ever seen
        $self->r->sunionstore("all_matches", "all_matches", "last_match:$search");
    }
}

sub completion_estimate {
    my($self) = @_;
    my $now = time;
    my $now_size = $self->r->llen('uri_queue');
    my $orig_size = $self->r->get('scan_size');
    my $launch_ts = $self->r->get('scan_start');

    # simple projection, we have done X per second, so how many seconds until done?
    my $uri_per_sec = ($orig_size-$now_size)/($now-$launch_ts);
    return parseInterval(seconds => int($now_size*$uri_per_sec), String => 1);
}

sub _build_r {
    return Redis->new();
}
sub reconnect_redis {
   my($self) = @_;
   $self->r->quit;
   $self->r(Redis->new());
}

__PACKAGE__->meta->make_immutable;
1;
