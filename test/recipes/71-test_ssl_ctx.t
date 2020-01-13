#! /usr/bin/env perl
# Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use warnings;
use Opentls::Test;

setup("tls_ctx_test");

plan tests => 1;
ok(run(test(["tls_ctx_test"])));
