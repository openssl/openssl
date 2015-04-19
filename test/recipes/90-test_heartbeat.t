#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use OpenSSL::Test;

setup("test_heartbeat");

plan tests => 1;
ok(run(test(["heartbeat_test"])), "running heartbeat_test");
