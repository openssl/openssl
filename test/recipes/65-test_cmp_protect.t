#! /usr/bin/env perl
# Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2019
# Copyright Siemens AG 2015-2019
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_cmp_protect");

plan skip_all => "This test is not supported in a no-cmp build"
    if disabled("cmp");

plan skip_all => "This test is not supported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

plan tests => 1;

ok(run(test(["cmp_protect_test",
             data_file("server.pem"),
             data_file("IR_protected.der"),
             data_file("IR_unprotected.der"),
             data_file("IP_PBM.der"),
             data_file("server.crt"),
             data_file("server.pem"),
             data_file("EndEntity1.crt"),
             data_file("EndEntity2.crt"),
             data_file("Root_CA.crt"),
             data_file("Intermediate_CA.crt")])));
