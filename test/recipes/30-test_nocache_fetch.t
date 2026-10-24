#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You may obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_dir/;
use OpenSSL::Test::Utils;

setup("test_nocache_fetch");

plan skip_all => "This test requires provider module support"
    if disabled("module");

plan skip_all => "Test only meaningful with the fetch cache enabled"
    if disabled("cached-fetch");

plan tests => 1;

$ENV{OSSL_TEST_PROVIDER_NO_CACHE} = "yes";

$ENV{OPENSSL_MODULES} = bldtop_dir("test");

ok(run(test(["nocache_fetch_test"])),
   "no-cache provider does not de-cache cacheable methods held across provider unload");
