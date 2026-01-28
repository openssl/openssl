#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test::Simple;

plan skip_all => "This test should not be run under valgrind"
    if ( defined $ENV{OSSL_USE_VALGRIND} );

{
    local $ENV{"ASAN_OPTIONS"} = "allocator_may_return_null=true";
    local $ENV{"MSAN_OPTIONS"} = "allocator_may_return_null=true";

    simple_test("test_mem_alloc_custom_fns", "mem_alloc_custom_fns_test");
}
