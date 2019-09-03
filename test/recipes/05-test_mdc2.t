#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_mdc2");

if (disabled("mdc2") || disabled("legacy")) {
    plan skip_all => "mdc2 is not supported by this OpenSSL build";
}

plan tests => 1;

ok(run(test(["mdc2test"])), "running mdc2test");
