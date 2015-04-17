#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_rand");

plan tests => 1;
ok(run(test(["randtest"])), "running randtest");
