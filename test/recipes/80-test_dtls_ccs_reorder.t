#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_dtls_ccs_reorder");

plan skip_all => "No DTLS protocols are supported"
    if alldisabled(available_protocols("dtls"));

plan tests => 1;

ok(run(test(["dtls_ccs_reorder_test",
             srctop_file("test/certs/servercert.pem"),
             srctop_file("test/certs/serverkey.pem")])),
   "DTLS CCS reorder tolerance tests");
