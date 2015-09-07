#! /usr/bin/perl

use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_verify_extra");

plan tests => 1;

ok(run(test(["verify_extra_test",
             top_file("test", "certs", "roots.pem"),
             top_file("test", "certs", "untrusted.pem"),
             top_file("test", "certs", "bad.pem")])));
