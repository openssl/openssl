#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_rc5");

plan tests => 1;
ok(run(test(["rc5test"])), "running rc5test");
