#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use strict;
use warnings;

use Opentls::Test::Simple;
use Opentls::Test;
use Opentls::Test::Utils;

setup("test_ige");

plan skip_all => "AES_ige support is disabled in this build"
    if disabled("deprecated")
       && (!defined config("api") || config("api") >= 30000);

simple_test("test_ige", "igetest");
