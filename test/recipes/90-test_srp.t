#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_srp");

plan tests => 1;
ok(run(test(["srptest"])), "running srptest");
