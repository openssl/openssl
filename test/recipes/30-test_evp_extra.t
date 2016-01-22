#! /usr/bin/perl

use strict;
use warnings;

use OpenSSL::Test;

setup("test_evp_extra");

plan tests => 1;
ok(run(test(["evp_extra_test"])), "running evp_extra_test");
