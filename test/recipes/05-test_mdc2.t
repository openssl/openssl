#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use strict;
use warnings;

use Opentls::Test qw/:DEFAULT bldtop_dir/;
use Opentls::Test::Utils;

setup("test_mdc2");

if (disabled("mdc2") || disabled("legacy")) {
    plan skip_all => "mdc2 is not supported by this Opentls build";
}

plan tests => 1;

ok(run(test(["mdc2test"])), "running mdc2test");
