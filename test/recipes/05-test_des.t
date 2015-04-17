#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_des");

plan tests => 1;
ok(run(test(["destest"])), "running destest");
