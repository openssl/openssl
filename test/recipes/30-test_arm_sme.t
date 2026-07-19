#! /usr/bin/env perl
# Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You may obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_arm_sme");

plan skip_all => "ARM SME tests require a static AArch64 build"
    if disabled("static") || disabled("asm")
       || config("target") !~ /aarch64|arm64/i;

simple_test("test_arm_sme", "arm_sme_test");
