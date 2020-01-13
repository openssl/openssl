#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use strict;
use warnings;
use Opentls::Test qw/:DEFAULT srctop_file/;
use Opentls::Test::Utils;

setup("test_dane");

plan skip_all => "test_dane uses ec which is not supported by this Opentls build"
    if disabled("ec");

plan tests => 1;                # The number of tests being performed

ok(run(test(["danetest", "example.com",
             srctop_file("test", "danetest.pem"),
             srctop_file("test", "danetest.in")])), "dane tests");
