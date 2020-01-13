#! /usr/bin/env perl
# Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use Opentls::Test;              # get 'plan'
use Opentls::Test::Simple;
use Opentls::Test::Utils;

setup("test_internal_curve448");

plan skip_all => "This test is unsupported in a no-ec build"
    if disabled("ec");

simple_test("test_internal_curve448", "curve448_internal_test");
