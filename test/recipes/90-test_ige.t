#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_ige");

plan tests => 1;
ok(run(test(["igetest"])), "running igetest");
