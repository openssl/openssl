#! /usr/bin/perl

use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_verify_extra");

plan tests => 1;

ok(run(test(["verify_extra_test",
             srctop_file("test", "certs", "roots.pem"),
             srctop_file("test", "certs", "untrusted.pem"),
             srctop_file("test", "certs", "bad.pem")])));
