#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/catfile/;
use File::Copy;
use File::Compare qw/compare_text/;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_enc");

# We do it this way, because setup() may have moved us around,
# so the directory portion of $0 might not be correct any more.
# However, the name hasn't changed.
my $testsrc = top_file("test","recipes",basename($0));

my $test = catfile(".", "p");

my $cmd = "openssl";

my @ciphers =
    map { s/^\s+//; s/\s+$//; split /\s+/ }
    run(app([$cmd, "list", "-cipher-commands"]), capture => 1);

plan tests => 1 + (scalar @ciphers)*2;

my $init = ok(copy($testsrc,$test));

if (!$init) {
    diag("Trying to copy $testsrc to $test : $!");
}

 SKIP: {
     skip "Not initialized, skipping...", 11 unless $init;

     foreach my $c (@ciphers) {
	 my %variant = ("$c" => [],
			"$c base64" => [ "-a" ]);

	 foreach my $t (sort keys %variant) {
	     my $cipherfile = "$test.$c.cipher";
	     my $clearfile = "$test.$c.clear";
	     my @e = ( "$c", "-bufsize", "113", @{$variant{$t}}, "-e", "-k", "test" );
	     my @d = ( "$c", "-bufsize", "157", @{$variant{$t}}, "-d", "-k", "test" );
	     if ($c eq "cat") {
		 $cipherfile = "$test.cipher";
		 $clearfile = "$test.clear";
		 @e = ( "enc", @{$variant{$t}}, "-e" );
		 @d = ( "enc", @{$variant{$t}}, "-d" );
	     }

	     ok(run(app([$cmd, @e],
			stdin => $test, stdout => $cipherfile))
		&& run(app([$cmd, @d],
			   stdin => $cipherfile, stdout => $clearfile))
		&& compare_text($test,$clearfile) == 0, $t);
	     unlink $cipherfile, $clearfile;
	 }
     }
}

unlink $test;
