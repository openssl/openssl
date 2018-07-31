#! /usr/bin/env perl
# Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2018
# Copyright Siemens AG 2015-2018
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.

use strict;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_cmp_internal");

plan skip_all => "This test is unsupported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

plan tests => 1;

ok(run(test(["cmp_internal_test",
             data_file("server.pem"),
             data_file("IR_protected.der"),
             data_file("IR_unprotected.der"),
             data_file("IP_PBM.der")])));
