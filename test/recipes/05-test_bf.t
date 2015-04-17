#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_bf");

plan tests => 1;
ok(run(test(["bftest"])), "running bftest");
