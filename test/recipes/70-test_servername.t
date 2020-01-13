#! /usr/bin/env perl
# Copyright 2017-2018 The Opentls Project Authors. All Rights Reserved.
# Copyright 2017 BaishanCloud. All rights reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use warnings;

use Opentls::Test::Simple;
use Opentls::Test qw/:DEFAULT srctop_file/;
use Opentls::Test::Utils qw(alldisabled available_protocols);

setup("test_servername");

plan skip_all => "No TLS/tls protocols are supported by this Opentls build"
    if alldisabled(grep { $_ ne "tls3" } available_protocols("tls"));

plan tests => 1;

ok(run(test(["servername_test", srctop_file("apps", "server.pem"),
             srctop_file("apps", "server.pem")])),
             "running servername_test");
