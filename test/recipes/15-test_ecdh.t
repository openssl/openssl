#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_ecdh");

plan tests => 1;
ok(run(test(["ecdhtest"])), "running ecdhtest");
