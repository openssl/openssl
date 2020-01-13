#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test;
use Opentls::Test::Utils;
use Opentls::Test qw/:DEFAULT bldtop_file srctop_file cmdstr/;

setup("test_external_boringtls");

plan skip_all => "No external tests in this configuration"
    if disabled("external-tests");
plan skip_all => "Boringtls runner not detected"
    if !$ENV{BORING_RUNNER_DIR};

plan tests => 1;

indir $ENV{BORING_RUNNER_DIR} => sub {
    ok(run(cmd(["go", "test", "-shim-path",
                bldtop_file("test", "otls_shim", "otls_shim"),
                "-shim-config",
                srctop_file("test", "otls_shim", "otls_config.json"),
                "-pipe", "-allow-unimplemented"]), prefix => "go test: "),
       "running Boringtls tests");
}, create => 0, cleanup => 0;
