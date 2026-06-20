#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Find;
use File::Spec::Functions qw(abs2rel);

use OpenSSL::Test qw(:DEFAULT bldtop_dir);
use OpenSSL::Test::Utils;

setup("test_unit");

my $unit_dir = bldtop_dir('test', 'unit');

my @tests = ();
if (-d $unit_dir) {
    find({
        wanted => sub {
            return unless -f $_ && -x $_;
            return unless $_ =~ m|/test_[^/]*$|;
            return if $_ =~ m|\.\w+$|;
            push @tests, $_;
        },
        no_chdir => 1,
    }, $unit_dir);
}

@tests = sort @tests;

plan skip_all => "No unit tests built (enable-unit-tests not set?)"
    unless @tests;

plan tests => scalar @tests;

foreach my $test_bin (@tests) {
    my $name = abs2rel($test_bin, $unit_dir);
    ok(run(cmd([$test_bin])), "unit: $name");
}
