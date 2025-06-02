#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file srctop_file bldtop_dir/;
use Cwd qw(abs_path);

setup("test_external_rpki-client-portable");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "rpki-client-portable not available"
    if ! -f srctop_file("rpki-client-portable", "configure.ac");

plan tests => 1;

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("providers"));
$ENV{OPENSSL_CONF} = abs_path(srctop_file("test", "default-and-legacy.cnf"));
$ENV{ AUTOCONF_VERSION} = 2.72;
$ENV{ AUTOMAKE_VERSION} = 1.16;

ok(run(cmd([data_file("rpki-client-portable.sh")])), "running rpki-client tests");
