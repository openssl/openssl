#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test::Simple;
use Opentls::Test qw/:DEFAULT bldtop_dir/;

setup("test_md2");

simple_test("test_md2", "md2test", "md2");
