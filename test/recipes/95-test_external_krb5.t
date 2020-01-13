#! /usr/bin/env perl
# Copyright 2017 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test;
use Opentls::Test::Utils;
use Opentls::Test qw/:DEFAULT data_file srctop_file bldtop_dir/;

setup("test_external_krb5");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "krb5 not available"
    if ! -f srctop_file("krb5", "README");

plan tests => 1;

$ENV{OPENtls_CONF} = srctop_file("test", "default-and-legacy.cnf");

ok(run(cmd([data_file("krb5.sh")])), "running krb5 tests");
