#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_jpake");

plan tests => 1;
ok(run(test(["jpaketest"])), "running jpaketest");
