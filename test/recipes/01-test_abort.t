#! /usr/bin/perl

use OpenSSL::Test;

setup("test_abort");

plan tests => 1;

is(run(test(["aborttest"])), 0, "Testing that abort is caught correctly");
