#! /usr/bin/env perl
# Copyright 2019 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use Opentls::Test qw(:DEFAULT bldtop_dir bldtop_file);
use Opentls::Test::Simple;
use Opentls::Test::Utils;

setup("test_internal_provider");

$ENV{OPENtls_MODULES} = bldtop_dir("test");
$ENV{OPENtls_CONF} = bldtop_file("test", "provider_internal_test.conf");

simple_test("test_internal_provider", "provider_internal_test");
