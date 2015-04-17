#! /usr/bin/perl

use strict;

use File::Spec::Functions;
use Test::More;

use OpenSSL::Test qw/:DEFAULT top_file/;

setup("check_testexes");

my $MINFO = top_file("MINFO");

plan tests => 2;
if (ok(open(FH,$MINFO), "MINFO exists")) {
    subtest 'Finding test scripts for the compiled test binaries' => sub {
	find_tests(\*FH); close FH;
    };
} else {
    diag("Expected to find $MINFO, please run 'make files' in the top directory");
}

#-------------
# test script finder
sub find_tests {
    my $fh = shift;
    while(<$fh>) {
	chomp;
	last if /^RELATIVE_DIRECTORY=test$/;
    }
    while(<$fh>) {
	chomp;
	last if /^EXE=/;
    }

    s/^EXE=\s*//;
    s/\s*$//;
    my %foundfiles =
	map {
	    my $key = $_;
	    s/_?test$//;
	    s/(sha\d+)t/$1/;
	    $key => top_file("test",
			     "recipes/[0-9][0-9]-test_$_.t"); } split(/\s+/, $_);

    plan tests => scalar (keys %foundfiles);

    foreach (sort keys %foundfiles) {
	my @check = glob($foundfiles{$_});
	ok(scalar @check, "check that a test for $_ exists")
	    || diag("Expected to find something matching $foundfiles{$_}");
    }
}
