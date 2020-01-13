#! /usr/bin/env perl
# Copyright 2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Opentls license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use Opentls::Test;              # get 'plan'
use Opentls::Test::Simple;
use Opentls::Test::Utils;

setup("test_internal_bn");

plan skip_all => "This test is unsupported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

simple_test("test_internal_bn", "bn_internal_test");
