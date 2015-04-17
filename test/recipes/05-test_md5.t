#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_md5");

plan tests => 1;
ok(run(test(["md5test"])), "running md5test");
