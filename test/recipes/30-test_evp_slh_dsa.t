#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_file srctop_dir);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_evp_slh_dsa");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

require(srctop_file("test", "recipes", "evp.pl"));

my @files = ();
push @files, qw(
                evppkey_slh_dsa_keygen.txt
                evppkey_slh_dsa_siggen.txt
                evppkey_slh_dsa_sigver.txt
               ) unless disabled("slh-dsa");

evp_tests(files => \@files);
