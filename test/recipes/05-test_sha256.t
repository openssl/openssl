#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_sha256", "sha256t", "sha");
