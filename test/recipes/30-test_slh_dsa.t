#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_slh_dsa");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'SLH-DSA is not supported in this build' if disabled('slh-dsa');
plan tests => 1;

ok(run(test(["slh_dsa_test"])), "running slh_dsa_test");
