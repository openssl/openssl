#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_d2i");

plan tests => 4;

ok(run(test(["d2i_test", "X509", "decode",
             srctop_file('test','d2i-tests','bad_cert.der')])),
   "Running d2i_test bad_cert.der");

ok(run(test(["d2i_test", "GENERAL_NAME", "decode",
             srctop_file('test','d2i-tests','bad_generalname.der')])),
   "Running d2i_test bad_generalname.der");

ok(run(test(["d2i_test", "ASN1_ANY", "BIO",
             srctop_file('test','d2i-tests','bad_bio.der')])),
   "Running d2i_test bad_bio.der");
# This test checks CVE-2016-2108. The data consists of an tag 258 and
# two zero content octets. This is parsed as an ASN1_ANY type. If the
# type is incorrectly interpreted as an ASN.1 INTEGER the two zero content
# octets will be reject as invalid padding and this test will fail.
# If the type is correctly interpreted it will by treated as an ASN1_STRING
# type and the content octets copied verbatim.
ok(run(test(["d2i_test", "ASN1_ANY", "OK",
             srctop_file('test','d2i-tests','high_tag.der')])),
   "Running d2i_test high_tag.der");
