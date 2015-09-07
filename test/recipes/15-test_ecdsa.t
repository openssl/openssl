#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_ecdsa", "ecdsatest", "ec");
