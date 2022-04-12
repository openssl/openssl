#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("locale tests");

plan skip_all => "Locale tests not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32)$/;

plan tests => 2;

$ENV{LANG} = "C";
ok(run(test(["localetest"])), "running localetest");

$ENV{LANG} = "tr_TR.UTF-8";
ok(run(test(["localetest"])), "running localetest with Turkish locale");
