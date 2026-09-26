#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_dir data_file/;
use OpenSSL::Test::Utils;

setup("test_provider_child_decoder");

plan skip_all => "module support is disabled" if disabled("module");

$ENV{OPENSSL_MODULES} = bldtop_dir("test");
$ENV{OPENSSL_CONF} = data_file("openssl.cnf");

plan tests => 2;

ok(run(app(["openssl", "genpkey", "-algorithm", "xorhmacsig",
            "-out", "xor-key.pem"])),
   "generate a key through an autoloaded child-context provider");
ok(run(app(["openssl", "pkey", "-in", "xor-key.pem", "-check", "-noout"])),
   "decode the key and release the child provider at process exit");
