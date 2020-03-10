#! /usr/bin/env perl
# Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2020
# Copyright Siemens AG 2015-2020
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_cmp_server");

plan skip_all => "This test is not supported in a no-cmp build"
    if disabled("cmp");

plan skip_all => "This test is not supported in a no-ec build"
    if disabled("ec");

plan tests => 1;

ok(run(test(["cmp_server_test",
             data_file("CR_protected_PBM_1234.der")])));
