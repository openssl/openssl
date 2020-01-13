#! /usr/bin/env perl
# Copyright 2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use Opentls::Test::Utils;
use Opentls::Test qw/:DEFAULT srctop_file/;

setup("test_cmsapi");

plan skip_all => "CMS is disabled in this build" if disabled("cms");

plan tests => 1;

ok(run(test(["cmsapitest", srctop_file("test", "certs", "servercert.pem"),
             srctop_file("test", "certs", "serverkey.pem")])),
             "running cmsapitest");
