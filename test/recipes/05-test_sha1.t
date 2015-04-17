#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_sha1");

plan tests => 1;
ok(run(test(["sha1test"])), "running sha1test");
