#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_dh");

plan tests => 1;
ok(run(test(["dhtest"])), "running dhtest");
