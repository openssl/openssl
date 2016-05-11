#! /usr/bin/env perl
# Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

if ($#ARGV < 0) {
    die "dirname.pl: too few arguments\n";
} elsif ($#ARGV > 0) {
    die "dirname.pl: too many arguments\n";
}

my $d = $ARGV[0];

if ($d =~ m|.*/.*|) {
    $d =~ s|/[^/]*$||;
} else {
    $d = ".";
}

print $d,"\n";
exit(0);
