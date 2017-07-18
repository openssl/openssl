#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw(:DEFAULT srctop_file);

my $test_name = "test_store_cache";
setup($test_name);

my @src_files =
    ( "test/testx509.pem",
      "test/testrsa.pem",
      "test/testrsapub.pem",
      "test/testcrl.pem",
      "apps/server.pem" );

plan tests => 1;

ok(run(test(['storetest', map { srctop_file($_) } @src_files])));
