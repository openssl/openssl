#! /usr/bin/env perl
# Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT bldtop_file srctop_file bldtop_dir with/;
use OpenSSL::Test::Utils;

setup("test_cli_list");

plan tests => 2;

ok(run(app(["openssl", "list", "-skey-managers"],
        stdout => "listout.txt")),
"List skey managers - default configuration");
open DATA, "listout.txt";
my @match = grep /secret key/, <DATA>;
close DATA;
ok(scalar @match > 1 ? 1 : 0, "Several skey managers are listed - default configuration");
