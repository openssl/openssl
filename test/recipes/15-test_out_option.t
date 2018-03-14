#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
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

setup("test_out_option");

plan skip_all => "'-out' option tests are not available on Windows"
    if $^O eq 'MSWin32';

plan tests => 11;

# The following patterns should be tested:
#
# path        dirname
# /usr/       /
# /           /
# .           .
# ..          .

test_illegal_path('/usr/');
test_illegal_path('/');
test_illegal_path('./');
test_illegal_path('../');

# Test for trying to create a file in a non-exist directory
my @chars = ("A".."Z", "a".."z", "0".."9");
my $rand_path = "";
$rand_path .= $chars[rand @chars] for 1..32;
$rand_path .= "/test.pem";

test_illegal_path($rand_path);
test_legal_path('test.pem');
unlink 'test.pem';

sub test_illegal_path {
    my $path = File::Spec->canonpath($_[0]);

    my $start = time();
    ok(!run(app([ 'openssl', 'genrsa', '-out', $path, '16384'])), "invalid output path: $path");
    my $end = time();
    # The above process should exit in 2 seconds if the path is not valid
    ok($end - $start < 2, "check time consumed");
}

sub test_legal_path {
    my $path = File::Spec->canonpath($_[0]);

    ok(run(app([ 'openssl', 'genrsa', '-out', $path, '2048'])), "valid output path: $path");
}
