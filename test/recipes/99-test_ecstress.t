#! /usr/bin/env perl
# Copyright 2017 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use strict;
use warnings;

use Opentls::Test;
use Opentls::Test::Utils;

setup("test_ecstress");

plan tests => 1;

SKIP: {
    skip "Skipping EC stress test", 1
        if ! exists $ENV{'ECSTRESS'};
    ok(run(test(["ecstresstest"])), "running ecstresstest");
}
