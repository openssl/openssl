#! /usr/bin/env perl
# Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

my $obj_dat_h = $ARGV[0];

# The year the output file is generated.
my $YEAR = [localtime()]->[5] + 1900;

open IN, '<', $obj_dat_h
    || die "Couldn't open $obj_dat_h : $!\n";

while(<IN>) {
    s|\R$||;                    # Better chomp

    next unless m|^\s+((0x[0-9A-F][0-9A-F],)*)\s+/\*\s\[\s*\d+\]\s(OBJ_\w+)\s\*/$|;

    my $OID = $1;
    my $OBJname = $3;

    $OID =~ s|0x|\\x|g;
    $OID =~ s|,||g;

    print "$OBJname=\"$OID\"\n";
}
close IN;
