#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;
use OpenSSL::Test::Utils;

setup("test_rsa");

plan tests => 5;

require_ok(top_file('test','recipes','tconversion.pl'));

ok(run(test(["rsa_test"])), "running rsatest");

 SKIP: {
     skip "Skipping rsa conversion test", 3
	 if disabled("rsa");

     subtest 'rsa conversions -- private key' => sub {
	 tconversion("rsa", top_file("test","testrsa.pem"));
     };
     subtest 'rsa conversions -- private key PKCS#8' => sub {
	 tconversion("rsa", top_file("test","testrsa.pem"), "pkey");
     };
     subtest 'rsa conversions -- public key' => sub {
	 tconversion("rsa", top_file("test","testrsapub.pem"), "rsa",
		     "-pubin", "-pubout");
     };
}
