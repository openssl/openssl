#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_file result_dir data_file/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);
use File::Path 2.00 qw(rmtree mkpath);

setup("test_quic_0rtt");

plan skip_all => "QUIC protocol is not supported by this OpenSSL build"
    if disabled('quic');

plan tests => 1;

#
# note we might need to add coverage for qlog
#

ok(run(test(["quic_0rtt_test",
             srctop_file("test", "certs", "servercert.pem"),
             srctop_file("test", "certs", "serverkey.pem")])));
