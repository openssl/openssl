#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions;
use FindBin;

my $openssldir = $ARGV[0] || "$FindBin::Bin/..";
my $versionheader = catfile($openssldir, 'include/openssl/opensslv.h');

my @version1macros = qw(
    OPENSSL_VERSION_TEXT
    SHLIB_VERSION_NUMBER
);
my @currentmacros = qw(
    OPENSSL_VERSION_MAJOR
    OPENSSL_VERSION_MINOR
    OPENSSL_VERSION_PATCH
    OPENSSL_VERSION_PRE_RELEASE
    OPENSSL_VERSION_BUILD_METADATA
    OPENSSL_SHLIB_VERSION
    );
my @result = qw(
    OPENSSL_VERSION_STR
    OPENSSL_FULL_VERSION_STR
    OPENSSL_VERSION_COMPAT
);

my $versionheadertxt = eval {
    local $/ = undef;
    open my $fh, $versionheader or die "Trying to open $versionheader: $!\n";
    my $x = <$fh>;
    close $fh;
    $x
};

die $@ if $@;                   # Pass on the eval exec error, if there was any

my $macroregex =
    '^#\s*define\s+('
    . join('|', @version1macros, @currentmacros)
    . ')\s+(?|(\d+)|"([^"]*)")';
my %macrovals =
    map { $_ =~ m|$macroregex| ? ( $1 => $2 ) : () }
    split m|\R|, $versionheadertxt;

if (defined $macrovals{OPENSSL_VERSION_MAJOR}) {
    # OpenSSL 3.0 and on
    $macrovals{OPENSSL_VERSION_STR} =
        join('.',
             $macrovals{OPENSSL_VERSION_MAJOR},
             $macrovals{OPENSSL_VERSION_MINOR},
             $macrovals{OPENSSL_VERSION_PATCH});
    $macrovals{OPENSSL_FULL_VERSION_STR} =
        join('',
             $macrovals{OPENSSL_VERSION_STR},
             $macrovals{OPENSSL_VERSION_PRE_RELEASE} // '',
             $macrovals{OPENSSL_VERSION_BUILD_METADATA} // '');
    $macrovals{OPENSSL_VERSION_COMPAT} = $macrovals{OPENSSL_VERSION_MAJOR};
} else {
    # OpenSSL before 3.0
    $macrovals{OPENSSL_FULL_VERSION_STR} =
        [ split m|\s+|, $macrovals{OPENSSL_VERSION_TEXT} ] -> [1];
    $macrovals{OPENSSL_VERSION_STR} =
        [ split m|-|, $macrovals{OPENSSL_FULL_VERSION_STR} ] -> [0];
    ( $macrovals{OPENSSL_VERSION_COMPAT} =
      $macrovals{OPENSSL_VERSION_STR} ) =~ s|(\d+\.\d+).*|$1|;
}

foreach (@result) {
    my $cmd = $^O eq 'MSWin32' ? "set " : "";
    if ($^O eq "VMS") {
        # For the benefit of VMS scripts, this can set CLI variables or define
        # logical names, all depending on the definition of PERL_ENV_TABLES.
        # For more info, see the perlvms manual page:
        # https://perldoc.perl.org/perlvms.html
        $ENV{$_}=$macrovals{$_};
    }
    print $cmd, $_, '=', $macrovals{$_}, "\n";
}
