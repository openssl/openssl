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

plan tests => 2;

ok(run(test(["d2i_test", "X509", "decode",
             srctop_file('test','d2i-tests','bad_cert.der')])),
   "Running d2i_test bad_cert.der");

ok(run(test(["d2i_test", "GENERAL_NAME", "decode",
             srctop_file('test','d2i-tests','bad_generalname.der')])),
   "Running d2i_test bad_generalname.der");
