#! /usr/bin/perl

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT top_file/;

setup("test_evp");

plan tests => 1;
ok(run(test(["evp_test", top_file("test", "evptests.txt")])),
   "running evp_test evptests.txt");
