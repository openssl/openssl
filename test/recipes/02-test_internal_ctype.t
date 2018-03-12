#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_internal_ctype");

plan skip_all => "This test is unsupported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

simple_test("test_internal_ctype", "ctype_internal_test");
