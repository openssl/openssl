#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
no strict 'refs';               # To be able to use strings as function refs
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use Errno qw(:POSIX);
use POSIX qw(strerror);

setup('test_errstr');

# In a cross compiled situation, there are chances that our
# application is linked against different C libraries than
# perl, and may thereby get different error messages for the
# same error.
# The safest is not to test under such circumstances.
plan skip_all => 'This is unsupported for cross compiled configurations'
    if config('CROSS_COMPILE');

# The same can be said when compiling OpenSSL with mingw configuration
# on Windows when built with msys perl.  Similar problems are also observed
# in MSVC builds, depending on the perl implementation used.
plan skip_all => 'This is unsupported on MSYS/MinGW or MSWin32'
    if $^O eq 'msys' or $^O eq 'MSWin32';

plan skip_all => 'OpenSSL is configured "no-autoerrinit" or "no-err"'
    if disabled('autoerrinit') || disabled('err');

# There's no simple perl flag or variable to recognise GNU/hurd, but we know
# that there's always a '/hurd' directory.
my $ishurd = -d '/hurd';

# $Errno::EXPORT_TAGS{POSIX} is an array of functions that return POSIX error
# codes, which is the common way to implement constants in Perl.  We map them
# to OpenSSL codes as required by the local system.  (special case: GNU/hurd)
my %posix_openssl_error_map =
    map {
        my $known_code = "Errno::$_"->();
        if ($ishurd) {
            $_ => ((($known_code >> 8) & 0x00FF0000)
                   | ($known_code & 0x0000FFFF))
        } else {
            $_ => $known_code
        }
    }
    @{$Errno::EXPORT_TAGS{POSIX}};

plan tests => scalar (keys %posix_openssl_error_map)
    +1                          # Checking that error 128 gives 'reason(128)'
    +1                          # Checking that error 0 gives the library name
    ;

foreach my $errname (sort keys %posix_openssl_error_map) {
    my $posix_errnum = "Errno::$errname"->();
    my $openssl_errnum = $posix_openssl_error_map{$errname};

 SKIP: {
        my $perr = eval {
            # Set $! to the error number...
            local $! = $posix_errnum;
            # ... and $! will give you the error string back
            $!
        };

        # We know that the system reasons are in OpenSSL error library 2
        my @oerr = run(app([ qw(openssl errstr),
                             sprintf("2%06x", $openssl_errnum) ]),
                       capture => 1);
        $oerr[0] =~ s|\R$||;
        @oerr = split_error($oerr[0]);

        skip "libcrypto hasn't registered any error string for $errname", 1
            if $oerr[3] =~ m|^reason\(\d+\)$|;
        ok($oerr[3] eq $perr, "($openssl_errnum) '$oerr[3]' == '$perr'");
    }
}

my @after = run(app([ qw(openssl errstr 2000080) ]), capture => 1);
$after[0] =~ s|\R$||;
@after = split_error($after[0]);
ok($after[3] eq "reason(128)", "(128) '$after[3]' == 'reason(128)'");

my @zero = run(app([ qw(openssl errstr 2000000) ]), capture => 1);
$zero[0] =~ s|\R$||;
@zero = split_error($zero[0]);
ok($zero[3] eq "system library", "(0) '$zero[3]' == 'system library'");

# For an error string "error:xxxxxxxx:lib:func:reason", this returns
# the following array:
#
# ( "xxxxxxxx", "lib", "func", "reason" )
sub split_error {
    # Limit to 5 items, in case the reason contains a colon
    my @erritems = split /:/, $_[0], 5;

    # Remove the first item, which is always "error"
    shift @erritems;

    return @erritems;
}
