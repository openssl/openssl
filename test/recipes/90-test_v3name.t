#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_v3name");

plan tests => 1;
ok(run(test(["v3nametest"])), "running v3nametest");
