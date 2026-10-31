#! /usr/bin/env perl
# Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;

setup("test_ecparam");

plan skip_all => "EC or EC2M isn't supported in this build"
    if disabled("ec") || disabled("ec2m");

my @valid = glob(data_file("valid", "*.pem"));
my @noncanon = glob(data_file("noncanon", "*.pem"));
my @invalid = glob(data_file("invalid", "*.pem"));

if (disabled("sm2")) {
    @valid = grep { !/sm2-.*\.pem/} @valid;
}

# The corpus is swept in a single process per set; the ecparam and
# pkeyparam applications themselves are covered by 20-test_app_ecparam.t.
plan tests => 3;

# The file names are written to a list file and that is passed instead:
# there are more of them than a test can be given arguments.
sub corpus_list {
    my $name = shift;

    open(my $fh, '>', $name) or die "Cannot write $name: $!";
    print $fh "$_\n" foreach (@_);
    close($fh);
    return $name;
}

ok(run(test(["ecparam_test", "valid", corpus_list("valid.lst", @valid)])),
   "Load and check valid parameters");

ok(run(test(["ecparam_test", "noncanon",
             corpus_list("noncanon.lst", @noncanon)])),
   "Load and check non-canonically encoded parameters");

ok(run(test(["ecparam_test", "invalid", corpus_list("invalid.lst", @invalid)])),
   "Reject invalid parameters");
