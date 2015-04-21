#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_md5", "md5test", "md5");
