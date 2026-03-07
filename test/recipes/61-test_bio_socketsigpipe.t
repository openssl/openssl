#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_bio_socketsigpipe");

plan skip_all => "SIGPIPE is not supported on Windows"
    if $^O eq 'MSWin32';

plan skip_all => "DJGPP target does not support this test"
    if config('target') =~ /djgpp/i;

plan skip_all => "sockets are disabled (no-sock)"
    if disabled("sock");

plan tests => 1;

ok(run(test(["bio_socket_sigpipe_test"])), "bio_socket_sigpipe_test");

