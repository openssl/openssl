#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_rc4", "rc4test", "rc4");
