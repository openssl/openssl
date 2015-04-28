#! /usr/bin/perl

use strict;
use warnings;

use Test::More 0.96;
use OpenSSL::Test;

setup("test_engine");

plan tests => 1;
ok(run(test(["enginetest"])), "running enginetest");
