#! /usr/bin/perl

use strict;

use File::Spec::Functions;
use Test::More 0.96;

use OpenSSL::Test qw/:DEFAULT top_file/;

setup("check_testexes");

my $MINFO = top_file("MINFO");

 SKIP: {
     my %foundfiles;
     my $numtests = 1;

     if (open(FH,$MINFO)) {
	 while(<FH>) {
	     chomp;
	     last if /^RELATIVE_DIRECTORY=test$/;
	 }
	 while(<FH>) {
	     chomp;
	     last if /^EXE=/;
	 }
	 close FH;

	 my $pathfix = sub { return shift; }; # noop
	 if ($^O eq "MSWin32") {
	     # Experience has shown that glob needs the backslashes escaped
	     # to handle the glob glob() gets served.  Otherwise, it sometimes
	     # considers the backslash an escape of the next character, most
	     # notably the [.
	     # (if the single backslash is followed by a *, however, the *
	     # doesn't seem to be considered escaped...  go figure...)
	     $pathfix = sub { shift; s/\\/\\\\/g; return $_; };
	 }
	 s/^EXE=\s*//;
	 s/\s*$//;
	 %foundfiles =
	     map {
		 my $key = $_;
		 s/_?test$//;
		 s/(sha\d+)t/$1/;
		 $key =>
		     $pathfix->(top_file("test", "recipes",
					 "[0-9][0-9]-test_$_.t")); } split(/\s+/, $_);
	 $numtests = scalar keys %foundfiles;
     }

     plan tests => $numtests;

     skip "because $MINFO found. If you want this test to run, please do 'perl util/mkfiles.pl > $MINFO'", 1
	 unless %foundfiles;

     foreach (sort keys %foundfiles) {
	 my @check = glob($foundfiles{$_});
	 ok(scalar @check, "check that a test for $_ exists")
	     || diag("Expected to find something matching $foundfiles{$_}");
     }
}
