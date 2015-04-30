#! /usr/bin/perl

use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT top_dir/;

setup("test_gost2814789");

$ENV{OPENSSL_ENGINES} =
    $ENV{BIN_D} ? top_dir($ENV{BIN_D}) : top_dir("engines", "ccgost");

plan tests => 1;
ok(run(test(["gost2814789test"])), 'running gost2814789test');
