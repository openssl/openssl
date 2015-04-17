#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_ecdsa");

plan tests => 1;
ok(run(test(["ecdsatest"])), "running ecdsatest");
