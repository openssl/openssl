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

# The primary assertion verifies that a cacheable method is installed in the
# method-store cache.  Under OPENSSL_NO_CACHED_FETCH every provider query is
# forced to no_cache (crypto/provider_core.c), so default-provider methods are
# correctly *not* cached and the assertion cannot hold by design.
plan skip_all => "Test only meaningful with the fetch cache enabled"
    if disabled("cached-fetch");

plan tests => 1;

# p_ossltest reads this on every query and, when set, requests no_cache for
# every operation (incl. ENCODER/DECODER/STORE), reproducing the relevant
# query-level no_cache behavior that oqsprovider exhibits on OpenSSL >= 3.5
# (it sets no_cache for every operation via its runtime filter).  The test
# program sets it as well.
$ENV{OSSL_TEST_PROVIDER_NO_CACHE} = "yes";

# p_ossltest.so is built under test/ (MODULES{noinst}); point the loader there.
$ENV{OPENSSL_MODULES} = bldtop_dir("test");

# The test has two detectors.  The primary one is allocator-independent: it
# verifies directly that a cacheable method fetched from the default provider
# (while p_ossltest is requesting no_cache) was installed in the libctx
# method-store cache.  On the buggy (temporary-store-proxy) code the method is
# de-cached, so that lookup fails regardless of platform or sanitizer.
#
# The secondary detector is the unload-then-free ordering the subtests drive
# after the cache check: on buggy code the de-cached method is freed during the
# provider unload and the following *_free then reads freed memory
# (use-after-free), surfaced by valgrind/ASan builds and by allocators that
# escalate it to a double free.

# Runs all three subtests (ENCODER, DECODER, STORE_LOADER); see the C source
# header for details.
ok(run(test(["nocache_fetch_test"])),
   "no-cache provider does not de-cache cacheable methods held across provider unload");
