#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_dir/;
use OpenSSL::Test::Utils;

setup("test_dtlsv1listen");

plan skip_all => "No DTLS protocols are supported by this OpenSSL build"
    if alldisabled(available_protocols("dtls"));

plan skip_all => "DH is disabled in this OpenSSL build" if disabled("dh");

plan tests => 1;

ok(run(test(["dtlsv1listentest", srctop_dir("test", "certs")])),
   "running dtlsv1listentest");
