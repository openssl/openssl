#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_sha1", "sha1test", "sha");
