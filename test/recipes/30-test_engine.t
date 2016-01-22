#! /usr/bin/perl

use strict;
use warnings;

use OpenSSL::Test;

setup("test_engine");

plan tests => 1;
ok(run(test(["enginetest"])), "running enginetest");
