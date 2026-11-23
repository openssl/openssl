#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test;

setup("test_safe_math");

plan tests => 2;

ok(run(test(["safe_math_test"])), "safe arithmetic");
ok(run(test(["safe_math_test_no_builtin"])), "safe arithmetic without builtins");
