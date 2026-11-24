#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (C) 2026, Advanced Micro Devices, all rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# The C test clears AVX512F, AVX512DQ, AVX512BW and AVX512VL so an
# AVX-512 VAES machine runs the 256-bit kernels instead of the 512-bit ones.

use OpenSSL::Test::Simple;

simple_test("test_aes_vaes256", "aes_vaes256_test");
