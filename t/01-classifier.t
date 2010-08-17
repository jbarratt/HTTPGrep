#!perl

use Test::More;
use HTTPGrep;

my $hg = HTTPGrep->new(search_pat => {}, ptr_pat => {A => '\.[abc]+(\d+)\.'}, user_agent => "unused");

my @tests = (
    ["foo.ac55.com", "A-55"],
);

for my $t (@tests) {
    cmp_ok($hg->find_classification($t->[0]), "eq", $t->[1]);
}


done_testing;

