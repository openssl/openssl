#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_mdc2", "mdc2test", "mdc2");
