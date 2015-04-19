#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_constant_time");

plan tests => 1;
ok(run(test(["constant_time_test"])), "running constant_time_test");
