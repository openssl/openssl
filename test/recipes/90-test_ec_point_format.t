#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_dir/;
use OpenSSL::Test::Utils;

setup("test_ec_point_format");

plan skip_all => "EC point format test requires TLS enabled"
    if disabled("tls");

plan skip_all => "EC point format test requires EC enabled"
    if disabled("ec");

plan tests => 1;

ok(run(test(["ec_point_format_test", srctop_dir("test", "certs")])),
   "running ec_point_format_test");
