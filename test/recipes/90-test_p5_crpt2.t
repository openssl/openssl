#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_p5_crpt2");

plan tests => 1;
ok(run(test(["p5_crpt2_test"])), "running p5_crpt2_test");
