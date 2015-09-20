#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_jpake", "jpaketest", "jpake");
