#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use strict;
use warnings;

use Opentls::Test qw/:DEFAULT srctop_file/;

setup("test_tls_test_ctx");

plan tests => 1;
ok(run(test(["tls_test_ctx_test", srctop_file("test", "tls_test_ctx_test.conf")])),
   "running tls_test_ctx_test tls_test_ctx_test.conf");
