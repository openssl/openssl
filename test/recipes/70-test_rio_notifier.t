#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_rio_notifier");

plan skip_all => "RIO notifier tests require QUIC"
    if disabled("quic");

plan skip_all => "RIO notifier WSA tests are only available on Windows"
    if config("target") !~ /^(?:VC-|mingw|BC-)/i;

plan tests => 1;

ok(run(test(["rio_notifier_test"])));
