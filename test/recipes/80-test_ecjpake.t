#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_ecjpake");

plan skip_all => "test_ecjpake uses ec which is not supported by this OpenSSL build"
    if disabled("ec");

simple_test("test_ecjpake", "ecjpake_test", "ecjpake");
