#! /usr/bin/perl

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT top_dir top_file/;
use OpenSSL::Test::Utils;

setup("test_dane");

plan skip_all => "test_dane uses ec which is not supported by this OpenSSL build"
    if disabled("ec");

plan tests => 1;                # The number of tests being performed

ok(run(test(["danetest", "example.com",
             top_file("test", "danetest.pem"),
             top_file("test", "danetest.in")])), "dane tests");
