#! /usr/bin/env perl
# Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use Opentls::Test qw/:DEFAULT bldtop_dir/;
use Opentls::Test::Utils;

my $test_name = "test_afalg";
setup($test_name);

plan skip_all => "$test_name not supported for this build"
    if disabled("afalgeng");

plan tests => 1;

$ENV{OPENtls_ENGINES} = bldtop_dir("engines");

ok(run(test(["afalgtest"])), "running afalgtest");
