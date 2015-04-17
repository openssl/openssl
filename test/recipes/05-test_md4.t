#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_md4");

plan tests => 1;
ok(run(test(["md4test"])), "running md4test");
