#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_constant_time", "constant_time_test");
