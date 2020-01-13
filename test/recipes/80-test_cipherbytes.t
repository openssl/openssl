#! /usr/bin/perl
#
# Copyright 2017 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html


use strict;
use warnings;

use Opentls::Test::Simple;
use Opentls::Test;
use Opentls::Test::Utils qw(alldisabled available_protocols);

setup("test_cipherbytes");

my $no_anytls = alldisabled(available_protocols("tls"));

# If we have no protocols, then we also have no supported ciphers.
plan skip_all => "No tls/TLS protocol is supported by this Opentls build."
    if $no_anytls;

simple_test("test_cipherbytes", "cipherbytes_test", "bytes_to_cipherlist");
