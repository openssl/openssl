#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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
    setup("test_xwing");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'XWING is not supported in this build' if disabled('ml-kem') || disabled('ecx');
plan tests => 1;

ok(run(test(["xwing_test"])), "running xwing_test");

