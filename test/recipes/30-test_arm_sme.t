#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;

use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_arm_sme");

# The test binary links against libcrypto.a (static) to reach internal
# assembly symbols such as aes_v8_sme_ctr32_encrypt_blocks.
plan skip_all => "This test requires static builds to be enabled"
    if disabled("static");

# The test is only meaningful on AArch64 – it self-skips on other arches,
# but we can save time by not even running it on obviously unrelated targets.
plan skip_all => "This test is only for AArch64 targets"
    unless config("target") =~ /aarch64|arm64/i;

simple_test("test_arm_sme", "arm_sme_test");
