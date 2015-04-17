#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_exp");

plan tests => 1;
ok(run(test(["exptest"])), "running exptest");
