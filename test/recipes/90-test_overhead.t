#! /usr/bin/env perl
# Copyright 2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test;
use Opentls::Test::Utils;

setup("test_overhead");

plan tests => 1;

ok(run(test(["cipher_overhead_test"])), "running cipher_overhead_test");
