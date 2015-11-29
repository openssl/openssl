#! /usr/bin/perl

use strict;

use File::Spec::Functions;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("check_testexes");

my $OpenSSL_ver = "";
my $Makefile = top_file("Makefile");
if (open(FH, $Makefile)) {
    $OpenSSL_ver =
	(map { s/\R//; s/^VERSION=([^\s]*)\s*$//; $1 } grep { /^VERSION=/ } <FH>)[0];
    close FH;
}

my $MINFO = top_file("MINFO");

plan skip_all => "because MINFO not found. If you want this test to run, please do 'perl util/mkfiles.pl > MINFO'"
    unless open(FH,$MINFO);

my $MINFO_ver = "";

while(<FH>) {
    s/\R//;	# chomp;
    if (/^VERSION=([^\s]*)\s*$/) {
	$MINFO_ver = $1;
    }
    last if /^RELATIVE_DIRECTORY=test$/;
}
while(<FH>) {
    s/\R//;	# chomp;
    last if /^EXE=/;
}
close FH;

plan skip_all => "because MINFO is not from this OpenSSL version. If you want this test to run, please do 'perl util/mkfiles.pl > MINFO'"
    unless $OpenSSL_ver eq $MINFO_ver;

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
