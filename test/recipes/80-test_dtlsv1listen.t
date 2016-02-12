#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_dtlsv1listen", "dtlsv1listentest", "dh");
