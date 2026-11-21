#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;

# test_kdf_pbkdf1_skey watches freed memory for the derived key
$ENV{OPENSSL_TEST_WATCH_FREED} = "1";

simple_test("test_evp_kdf", "evp_kdf_test");
