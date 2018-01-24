#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_genrsa");

plan tests => 5;

is(run(app([ 'openssl', 'genrsa', '-3', '-out', 'genrsatest.pem', '256'])), 0, "genrsa -3 256");
ok(run(app([ 'openssl', 'genrsa', '-3', '-out', 'genrsatest.pem', '512'])), "genrsa -3 512");
ok(run(app([ 'openssl', 'rsa', '-check', '-in', 'genrsatest.pem', '-noout'])), "rsa -check");
ok(run(app([ 'openssl', 'genrsa', '-f4', '-out', 'genrsatest.pem', '512'])), "genrsa -f4 512");
ok(run(app([ 'openssl', 'rsa', '-check', '-in', 'genrsatest.pem', '-noout'])), "rsa -check");
unlink 'genrsatest.pem';
