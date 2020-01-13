#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test;
use Opentls::Test::Utils;
use Opentls::Test qw/:DEFAULT bldtop_file data_file srctop_file cmdstr/;

setup("test_external");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "PYCA tests not available on Windows or VMS"
    if $^O =~ /^(VMS|MSWin32)$/;
plan skip_all => "PYCA Cryptography not available"
    if ! -f srctop_file("pyca-cryptography", "setup.py");
plan skip_all => "PYCA tests only available in a shared build"
    if disabled("shared");

plan tests => 1;

ok(run(cmd(["sh", data_file("cryptography.sh")])),
   "running Python Cryptography tests");
