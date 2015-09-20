#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_sha512", "sha512t", "sha");
