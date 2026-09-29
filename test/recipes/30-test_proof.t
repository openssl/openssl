#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_dir);
use OpenSSL::Test::Utils;

setup("test_proof");

plan skip_all => "test_proof needs ML-DSA" if disabled("ml-dsa");

plan tests => 1;

ok(run(test(["proof_test", srctop_dir("test", "mtc")])),
   "running proof_test");
