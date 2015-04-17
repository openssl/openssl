#! /usr/bin/perl

use strict;

use File::Spec::Functions;
use Test::More;

use lib 'testlib';
use OpenSSL::Test;

setup("check_testalltests");

my $Makefile = top_file("test","Makefile");

plan tests => 2;
if (ok(open(FH,$Makefile), "test/Makefile exists")) {
    subtest 'Finding test scripts for the alltests target' => sub {
	find_tests(\*FH); close FH;
    };
} else {
    diag("Expected to find $Makefile");
}

#-------------
# test script finder
sub find_tests {
    my $fh = shift;
    my $line;
    while(<$fh>) {
	chomp;
	$line = $_;
	last if /^alltests:/;
    }
    while(<$fh>) {
	chomp;
	my $l = $_;
	$line =~ s/\\\s*$/$l/;
	last if $line !~ /\\\s*$/;
    }
    close $fh;
    $line =~ s/^alltests:\s*//;

    # It's part of the test_ssl recipe
    $line =~ s/\s+test_ss\s+/ /;

    # It's split into sha1, sha256 and sha512
    $line =~ s/\s+test_sha\s+/ test_sha1 test_sha256 test_sha512 /;

    my %foundfiles =
	map {
	    s/^test_//;
	    $_ => top_file("test",
			   "recipes/[0-9][0-9]-test_$_.t"); } split(/\s+/,
								    $line);

    plan tests => scalar (keys %foundfiles);

    foreach (sort keys %foundfiles) {
	my @check = glob($foundfiles{$_});
	ok(scalar @check, "check that a test for $_ exists")
	    || diag("Expected to find something matching $foundfiles{$_}");
    }
}
