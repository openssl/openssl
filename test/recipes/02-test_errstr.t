#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;
use POSIX;

setup('test_errstr');

# We actually have space for up to 4095 error messages,
# numerically speaking...  but we're currently only using
# numbers 1 through 127.
plan tests => 128;

my $i;

for ($i = 1; $i < 128; $i++) {
    # We know that the system reasons are in library 2
    my @oerr = run(app([ qw(openssl errstr), sprintf("2%06x", $i) ]),
                   capture => 1);
    $oerr[0] =~ s|\R$||;
    $oerr[0] =~ s|.*system library:||g; # The actual message is last

    my $perr = strerror($i);
    if ($perr =~ m|Unknown error $i|) {
        ok($oerr[0] eq 'unknown', "($i) '$oerr[0]' == 'unknown' ('$perr')");
    } else {
        ok($oerr[0] eq $perr, "($i) '$oerr[0]' == '$perr'");
    }
}

my @after = run(app([ qw(openssl errstr), sprintf("2%06x", $i) ]),
                capture => 1);
$after[0] =~ s|\R$||;
$after[0] =~ s|.*system library:||g;
ok($after[0] eq "reason($i)", "($i) '$after[0]' == 'reason($i)'");
