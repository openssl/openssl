#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_sha512");

plan tests => 1;
ok(run(test(["sha512t"])), "running sha512t");
