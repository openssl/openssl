#! /usr/bin/perl

use strict;

use File::Spec::Functions;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("check_testexes");

my $MINFO = top_file("MINFO");

plan skip_all => "because MINFO not found. If you want this test to run, please do 'perl util/mkfiles.pl > MINFO'"
    unless open(FH,$MINFO);

while(<FH>) {
    chomp;
    last if /^RELATIVE_DIRECTORY=test$/;
}
while(<FH>) {
    chomp;
    last if /^EXE=/;
}
close FH;

s/^EXE=\s*//;
s/\s*$//;
my @expected_tests =
    map { s/\..*$//;		# Remove extension
	  s/_?test$//;		# Remove 'test', possibly prefixed with '_'
	  s/(sha\d+)t/$1/;	# sha comes with no t at the end
	  $_; } split(/\s+/, $_);

plan tests => scalar @expected_tests;

my @found_tests =
    map { basename($_) } glob(top_file("test", "recipes", "*.t"));

foreach my $test (sort @expected_tests) {
    ok(scalar(grep(/^[0-9][0-9]-test_$test\.t$/, @found_tests)),
       "check that a test for $test exists")
	|| diag("Expected to find something matching '[0-9][0-9]-test_$test.t'");
}
