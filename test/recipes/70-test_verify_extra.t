#! /usr/bin/perl

use OpenSSL::Test qw/:DEFAULT top_file/;

my $prog = "verify_extra_test";

setup("test_verify_extra");

plan tests => 1;

my $test = test([$prog, top_file("test", "certs/roots.pem"),
                        top_file("test", "certs/untrusted.pem"),
                        top_file("test", "certs/bad.pem")]);

ok(run($test), "running $prog");
