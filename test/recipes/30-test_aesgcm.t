#! /usr/bin/env perl
# Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test qw/:DEFAULT/;
use OpenSSL::Test::Utils;

setup("test_aesgcm");
plan skip_all => "AES-GCM is disabled" if disabled("aes") || disabled("gcm");
plan tests => 5;

ok(run(test(["aesgcmtest"])), "AES-GCM with default dispatch");

{
    # Only mask detected capabilities; never enable an unsupported instruction.
    local $ENV{OPENSSL_ia32cap} = ":~0x10000:~0x0:~0x0:~0x0";
    ok(run(test(["aesgcmtest"])), "AES-GCM without AVX-512F");
    $ENV{OPENSSL_ia32cap} = ":~0x20000010000:~0x0:~0x0:~0x0";
    ok(run(test(["aesgcmtest"])), "AES-GCM without AVX-512F or VAES");
    $ENV{OPENSSL_ia32cap} = ":~0x40000010000:~0x0:~0x0:~0x0";
    ok(run(test(["aesgcmtest"])), "AES-GCM without AVX-512F or VPCLMULQDQ");
    $ENV{OPENSSL_ia32cap} = ":~0x10020:~0x0:~0x0:~0x0";
    ok(run(test(["aesgcmtest"])), "AES-GCM without AVX-512F or AVX2");
}
