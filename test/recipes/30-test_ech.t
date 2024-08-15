#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2022, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file/;

setup("test_ech");

plan skip_all => "ECH tests not supported in this build"
    if !disabled("fips") || disabled("ech") || disabled("tls1_3") || disabled("ec") || disabled("tls1_2") || disabled("ecx");

plan tests => 1;

ok(run(test(["ech_test", srctop_dir("test", "certs")])))
