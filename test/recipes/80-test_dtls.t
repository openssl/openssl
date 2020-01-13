#! /usr/bin/env perl
# Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use Opentls::Test::Utils;
use Opentls::Test qw/:DEFAULT srctop_file/;

setup("test_dtls");

plan skip_all => "No DTLS protocols are supported by this Opentls build"
    if alldisabled(available_protocols("dtls"));

plan tests => 1;

ok(run(test(["dtlstest", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])), "running dtlstest");
