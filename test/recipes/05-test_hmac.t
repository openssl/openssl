#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_hmac");

plan tests => 1;
ok(run(test(["hmactest"])), "running hmactest");
