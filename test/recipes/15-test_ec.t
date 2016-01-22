#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;
use OpenSSL::Test::Utils;

setup("test_ec");

plan tests => 5;

require_ok(top_file('test','recipes','tconversion.pl'));

ok(run(test(["ectest"])), "running ectest");

 SKIP: {
     skip "Skipping ec conversion test", 3
	 if disabled("ec");

     subtest 'ec conversions -- private key' => sub {
	 tconversion("ec", top_file("test","testec-p256.pem"));
     };
     subtest 'ec conversions -- private key PKCS#8' => sub {
	 tconversion("ec", top_file("test","testec-p256.pem"), "pkey");
     };
     subtest 'ec conversions -- public key' => sub {
	 tconversion("ec", top_file("test","testecpub-p256.pem"), "ec", "-pubin", "-pubout");
     };
}
