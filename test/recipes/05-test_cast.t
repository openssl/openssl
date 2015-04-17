#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_cast");

plan tests => 1;
ok(run(test(["casttest"])), "running casttest");
