#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_dir/;

setup("test_evp_extra");

plan tests => 2;

ok(run(test(["evp_extra_test"])), "running evp_extra_test");
ok(run(test(["evp_extra_test2"])), "running evp_extra_test2");
