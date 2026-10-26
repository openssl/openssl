#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw(:DEFAULT srctop_dir);
use OpenSSL::Test::Utils;

setup("test_internal_x509_view");

plan skip_all => "This test requires ED25519"
    if disabled("ecx");

plan tests => 1;

ok(run(test(["x509_view_internal_test", srctop_dir("test", "certs")])),
    "running x509_view_internal_test");
