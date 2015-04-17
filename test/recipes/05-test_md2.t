#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_md2");

plan tests => 1;
ok(run(test(["md2test"])), "running md2test");
