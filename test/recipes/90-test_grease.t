#! /usr/bin/env perl
# Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir/;

BEGIN {
    setup("test_grease");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan tests => 1;

ok(run(test(["grease_test", srctop_dir("test", "certs")])), "running grease_test");
