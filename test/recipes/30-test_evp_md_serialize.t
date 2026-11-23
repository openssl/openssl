#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT);
use OpenSSL::Test::Utils;

setup("test_evp_md_serialize");

plan skip_all => "This test is only relevant for s390x with assembler enabled"
    if disabled("asm") || (target("asm_arch") // "") ne "s390x";

plan tests => 6;

# The CPACF optimizations are selected at process start by OPENSSL_s390xcap,
# so the serialized state is handed over between two processes. The masks
# below clear the following function bits (see OPENSSL_s390xcap(3)), which
# makes the providers fall back to the software implementations:
#   KIMD-SHA-256 and KIMD-SHA-512 (bits 2 and 3, mask 0x3000000000000000),
#   KIMD/KLMD SHA3-224..512 and SHAKE-128/256 (bits 32-37, mask 0xfc000000).
my $nocpacf = "kimd:~0x30000000fc000000:~0;klmd:~0xfc000000:~0";

# Serialized with CPACF (default), deserialized with the software code
ok(run(test(["evp_md_serialize_test", "write", "state_hw"])),
   "serialize with default optimizations");
{
    local $ENV{OPENSSL_s390xcap} = $nocpacf;
    ok(run(test(["evp_md_serialize_test", "read", "state_hw"])),
       "deserialize with s390x CPACF SHA-2/SHA-3 disabled");
}

# Serialized with the software code, deserialized with CPACF (default)
{
    local $ENV{OPENSSL_s390xcap} = $nocpacf;
    ok(run(test(["evp_md_serialize_test", "write", "state_sw"])),
       "serialize with s390x CPACF SHA-2/SHA-3 disabled");
}
ok(run(test(["evp_md_serialize_test", "read", "state_sw"])),
   "deserialize with default optimizations");

# Re-initializing a used context must not depend on state left in it
ok(run(test(["evp_md_serialize_test", "reuse"])),
   "reuse a context with default optimizations");
{
    local $ENV{OPENSSL_s390xcap} = $nocpacf;
    ok(run(test(["evp_md_serialize_test", "reuse"])),
       "reuse a context with s390x CPACF SHA-2/SHA-3 disabled");
}
