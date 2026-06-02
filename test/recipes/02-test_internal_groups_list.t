#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils qw(disabled);

setup("test_internal_groups_list");

plan skip_all => "needs ECX enabled"
    if disabled("ecx");

plan skip_all => "needs EC enabled"
    if disabled("ec");

plan tests => 1;

ok(run(test(["groups_list_struct_test"])),
   "running groups_list_struct_test");
