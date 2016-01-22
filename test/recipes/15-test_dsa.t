#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT top_file/;
use OpenSSL::Test::Utils;

setup("test_dsa");

plan tests => 6;

require_ok(top_file('test','recipes','tconversion.pl'));

ok(run(test(["dsatest"])), "running dsatest");
ok(run(test(["dsatest", "-app2_1"])), "running dsatest -app2_1");

 SKIP: {
     skip "Skipping dsa conversion test", 3
	 if disabled("dsa");

     subtest 'dsa conversions -- private key' => sub {
	 tconversion("dsa", top_file("test","testdsa.pem"));
     };
     subtest 'dsa conversions -- private key PKCS#8' => sub {
	 tconversion("dsa", top_file("test","testdsa.pem"), "pkey");
     };
     subtest 'dsa conversions -- public key' => sub {
	 tconversion("dsa", top_file("test","testdsapub.pem"), "dsa",
		     "-pubin", "-pubout");
     };
}
