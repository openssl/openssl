#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_ecparam");

plan skip_all => "EC isn't supported in this build"
    if disabled("ec") || disabled("ec2m");

my @valid = ();
my @invalid = ();

if (defined $ENV{'fips'}) {
    @valid = glob(data_file("fips", "*.pem"));
    my @notfips = glob(data_file("valid", "*.pem"));
    @invalid = glob(data_file("invalid", "*.pem"));

    push(@invalid, @notfips);
} else {
    @valid = glob(data_file("valid", "*.pem"));
    my @fips = glob(data_file("fips", "*.pem"));
    @invalid = glob(data_file("invalid", "*.pem"));

    push(@valid, @fips);
}

plan tests => scalar @valid + scalar @invalid;

foreach (@valid) {
    ok(run(app([qw{openssl ecparam -noout -check -in}, $_])));
}

foreach (@invalid) {
    ok(!run(app([qw{openssl ecparam -noout -check -in}, $_])));
}
