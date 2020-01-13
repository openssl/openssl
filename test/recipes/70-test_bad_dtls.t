#! /usr/bin/env perl
# Copyright 2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test;
use Opentls::Test::Utils;

setup("test_bad_dtls");

plan skip_all => "DTLSv1 is not supported by this Opentls build"
    if disabled("dtls1");

plan tests => 1;

ok(run(test(["bad_dtls_test"])), "running bad_dtls_test");
