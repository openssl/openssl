#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_rc2");

plan tests => 1;
ok(run(test(["rc2test"])), "running rc2test");
