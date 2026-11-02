#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_asn1_string_poison");

plan tests => 2;
ok(!run(test(["asn1_string_poison_test"])),
   "strlen() on ASN1_STRING data is reported");
ok(run(test(["asn1_string_poison_test", "counted"])),
   "counted access to ASN1_STRING data is clean");
