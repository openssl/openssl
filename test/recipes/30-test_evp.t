#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_evp");

my @files = ( "evpciph.txt", "evpdigest.txt", "evpencod.txt", "evpkdf.txt",
    "evpmac.txt", "evppbe.txt", "evppkey.txt" );

plan tests => scalar(@files);

foreach my $f ( @files ) {
    ok(run(test(["evp_test", srctop_file("test", "$f")])),
       "running evp_test $f");
}
