#! /usr/bin/env perl
# Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir srctop_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_hqc");
}

plan skip_all => 'HQC is not supported in this build' if disabled('hqc');
plan tests => 1;

ok(run(test(["hqc_test"])), "running hqc_test");
