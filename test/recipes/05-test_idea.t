#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_idea");

plan tests => 1;
ok(run(test(["ideatest"])), "running ideatest");
