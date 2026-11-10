#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw(:DEFAULT bldtop_dir);
use OpenSSL::Test::Utils;

setup("test_childrand_teardown");

plan skip_all => "module support is disabled" if disabled("module");

$ENV{OPENSSL_MODULES} = bldtop_dir("test");

plan tests => 1;

# The interesting part happens at process exit; a failure manifests as a
# crash there, which makes run() report failure.
ok(run(test(["childrand_teardown_test"])),
   "child libctx RAND thread state outlives the parent method store");
