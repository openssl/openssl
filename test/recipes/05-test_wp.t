#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_wp");

plan tests => 1;
ok(run(test(["wp_test"])), "running wp_test");
