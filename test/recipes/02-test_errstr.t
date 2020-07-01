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

# We actually have space for up to 4095 error messages,
# numerically speaking...  but we're currently only using
# numbers 1 through 127.
# This constant should correspond to the same constant
# defined in crypto/err/err.c, or at least must not be
# assigned a greater number.
use constant NUM_SYS_STR_REASONS => 127;

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

# We use Errno::EXPORT_OK as a list of known errno values on the current
# system.  libcrypto's ERR should either use the same string as perl, or if
# it was outside the range that ERR looks at, ERR gives the reason string
# "reason(nnn)", where nnn is the errno number.

plan tests => scalar @Errno::EXPORT_OK
    +1                          # Checking that error 128 gives 'reason(128)'
    +1                          # Checking that error 0 gives the library name
    ;

foreach my $errname (@Errno::EXPORT_OK) {
    # The error names are perl constants, which are implemented as functions
    # returning the numeric value of that name.
    my $errnum = "Errno::$errname"->();

  SKIP: {
      # ERR only handles errnos that fit in 24 bits.  Numbers beyond that are
      # trunkated and give false results.
      skip "$errnum is larger than a 24 bit value, not supported", 1
          if ($errnum & ~0xFFFFFF) != 0;

      my $perr = eval {
          # Set $! to the error number...
          local $! = $errnum;
          # ... and $! will give you the error string back
          $!
      };

      # We know that the system reasons are in OpenSSL error library 2
      my @oerr = run(app([ qw(openssl errstr), sprintf("2%06x", $errnum) ]),
                     capture => 1);
      $oerr[0] =~ s|\R$||;
      @oerr = split_error($oerr[0]);
      # Optional, if libcrypto didn't capture the text
      my $rerr = "reason($errnum)";
      ok($oerr[3] eq $perr || $oerr[3] eq $rerr,
         $oerr[3] eq $perr
         ? "($errnum) '$oerr[3]' == '$perr'"
         : "'$oerr[3]' == '$rerr'");
    }
}

my @after = run(app([ qw(openssl errstr 2000100) ]), capture => 1);
$after[0] =~ s|\R$||;
@after = split_error($after[0]);
ok($after[3] eq "reason(256)", "(256) '$after[3]' == 'reason(256)'");

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
