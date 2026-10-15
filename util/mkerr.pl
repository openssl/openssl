#! /usr/bin/env perl
# Copyright 1999-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Writes one generated error header or C source to standard output, from
# the config file crypto/err/openssl.ec and the reason file next to it,
# crypto/err/openssl.txt.  crypto/err/README.md describes both.
#
# usage: mkerr.pl [-conf FILE] -emit FILE

use strict;
use warnings;

use File::Basename;
use File::Spec::Functions qw(abs2rel catfile rel2abs);

use lib ".";

my $config = "crypto/err/openssl.ec";
my $emit;

my @t = localtime();
my $YEAR = $t[5] + 1900;

while (@ARGV) {
    my $arg = shift @ARGV;

    if ($arg eq "-conf") {
        $config = shift @ARGV;
    } elsif ($arg eq "-emit") {
        $emit = shift @ARGV;
    } else {
        die "usage: $0 [-conf FILE] -emit FILE\n";
    }
}
die "usage: $0 [-conf FILE] -emit FILE\n"
    unless defined $config && defined $emit;

# Data parsed out of the config and reason files.
my %hpubinc;    # lib -> public header
my %libpubinc;  # public header -> lib
my %hprivinc;   # lib -> private header
my %libprivinc; # private header -> lib
my %cskip;      # error_file -> lib
my %errorfile;  # lib -> error file name
my %rextra;     # reason name -> code fixed by an R line in the config file
my %rcodes;     # reason name -> value
my %strings;    # reason name -> text

open(my $in, '<', $config) or die "Can't open config file $config, $!\n";
while (<$in>) {
    s|\R$||;
    next if /^#/ || /^$/;
    if (/^L\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*$/) {
        my $lib = $1;
        my $pubhdr = $2;
        my $err = $3;
        my $privhdr = $4 // 'NONE';

        $hpubinc{$lib} = $pubhdr;
        $libpubinc{$pubhdr} = $lib;
        $hprivinc{$lib} = $privhdr;
        $libprivinc{$privhdr} = $lib;
        $cskip{$err} = $lib;
        $errorfile{$lib} = $err;
        die "Public header file must be in include/openssl ($pubhdr is not)\n"
            if $err ne 'NONE' && $pubhdr ne 'NONE'
               && $pubhdr !~ m|^include/openssl/|;
    } elsif (/^R\s+(\S+)\s+(\S+)/) {
        $rextra{$1} = $2;
    } else {
        die "Illegal config line $_\n";
    }
}
close $in;

my @libs = grep { $errorfile{$_} ne 'NONE' } keys %errorfile;
my $reasons = catfile(dirname($config), "openssl.txt");
my %numbers;    # lib -> number -> line it is used on
my %name_line;  # reason name -> line it is defined on
my $errors = 0;

sub fail
{
    my ($line, $msg) = @_;

    print STDERR "$reasons:$line: $msg\n";
    $errors++;
}

open($in, '<', $reasons) or die "Can't open $reasons, $!\n";
while (<$in>) {
    s|\R$||;
    next if /^#/ || /^$/;

    my $line = $.;
    my @field = split /:/, $_, -1;

    if (@field != 3) {
        fail($line, "a line has three fields, NUMBER:NAME:TEXT");
        next;
    }

    my ($code, $name, $text) = @field;
    my @owner = grep { index($name, "${_}_R_") == 0 } @libs;

    if (@owner != 1) {
        fail($line, "$name is not <LIB>_R_<REASON> for a library in $config");
        next;
    }
    if ($code !~ /^\d+$/) {
        fail($line, "\"$code\" is not a number");
        next;
    }
    if ($text eq '' || $text =~ /^\s|\s$/) {
        fail($line, "the text is empty or has spaces at either end");
        next;
    }

    my $lib = $owner[0];

    if (defined $name_line{$name}) {
        fail($line, "$name is already defined on line $name_line{$name}");
        next;
    }
    $name_line{$name} = $line;
    if (defined $numbers{$lib}{$code}) {
        fail($line, "$code is already used by $lib on line $numbers{$lib}{$code}");
    } elsif (exists $rextra{$name} && $rextra{$name} != $code) {
        fail($line, "$name is $code here but $rextra{$name} in $config");
    }
    $numbers{$lib}{$code} = $line;
    $rcodes{$name} = $code;
    $strings{$name} = $text;
}
close $in;

die "$reasons: $errors error(s)\n" if $errors;

if (defined $libprivinc{$emit} && $emit ne 'NONE') {
    write_internal_header($libprivinc{$emit}, \*STDOUT);
} elsif (defined $libpubinc{$emit} && $emit ne 'NONE') {
    write_public_header($libpubinc{$emit}, \*STDOUT);
} elsif (defined $cskip{$emit} && $emit ne 'NONE') {
    write_c_source($cskip{$emit}, \*STDOUT);
} else {
    die "$emit is not a file the config file $config knows about\n";
}

exit;

sub reasons_of
{
    my $lib = shift;

    return sort grep { index($_, "${lib}_R_") == 0 } keys %rcodes;
}

sub lib_disablable
{
    my $lib = shift;

    # configdata is large and only needed when a file is actually
    # written, so it is loaded lazily here rather than at startup.
    require configdata;

    # Flag if the sub-library is disablable.
    # There are a few exceptions, where disabling the sub-library
    # doesn't actually remove the whole sub-library, but rather
    # implements it with a NULL backend or keeps part of it: no-http
    # still builds http_lib.c for URL parsing, so the HTTP reason
    # codes must remain visible.
    return do {
        # The 'once' warning does not know that require defines these.
        no warnings 'once';

        ($lib ne "SSL" && $lib ne "ASYNC" && $lib ne "DSO"
         && $lib ne "HTTP"
         && (grep { $lib eq uc $_ } @configdata::disablables,
                                    @configdata::disablables_int));
    };
}

# Write the internal header file for $lib
sub write_internal_header
{
    my ( $lib, $fh ) = @_;
    my @reasons = reasons_of($lib);
    my $disablable = lib_disablable($lib);
    my $hfile = $hprivinc{$lib};
    my $guard = $hfile;

    if ($guard =~ m|^include/|) {
        $guard = $';
    } else {
        $guard = basename($guard);
    }
    $guard = "OSSL_" . join('_', split(m|[./]|, uc $guard));

    print $fh <<"EOF";
/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 2020-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the \"License\").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef $guard
#define $guard
#pragma once

#include <openssl/opensslconf.h>
#include <openssl/symhacks.h>

#ifdef __cplusplus
extern \"C\" {
#endif

EOF
    my $indent = ' ';
    if ($disablable) {
        print $fh <<"EOF";
#ifndef OPENSSL_NO_${lib}

EOF
        $indent = "  ";
    }
    print $fh <<"EOF";
int ossl_err_load_${lib}_strings(void);
EOF

    # A library without a public header has its reason codes here.
    if ($hpubinc{$lib} eq 'NONE') {
        print $fh "\n/*\n * $lib reason codes.\n */\n";
        foreach my $i ( @reasons ) {
            print $fh "#define $i $rcodes{$i}\n";
        }
        print $fh "\n";
    }

    # This doesn't go all the way down to zero, to allow for the ending
    # brace for 'extern "C" {'.
    while (length($indent) > 1) {
        $indent = substr $indent, 0, -1;
        print $fh "#endif\n";
    }

    print $fh <<"EOF";

#ifdef __cplusplus
}
#endif
#endif
EOF
}

# Write the public header file for $lib
sub write_public_header
{
    my ( $lib, $fh ) = @_;
    my @reasons = reasons_of($lib);
    my $disablable = lib_disablable($lib);
    my $extra_include =
        $lib ne 'SSL'
        ? "#include <openssl/cryptoerr_legacy.h>\n"
        : "#include <openssl/sslerr_legacy.h>\n";
    my $hfile = $hpubinc{$lib};
    my $guard = $hfile;

    $guard =~ s|^include/||;
    $guard = join('_', split(m|[./]|, uc $guard));

    print $fh <<"EOF";
/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the \"License\").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef $guard
#define $guard
#pragma once

#include <openssl/opensslconf.h>
#include <openssl/symhacks.h>
$extra_include
EOF
    my $indent = ' ';
    if ($disablable) {
        print $fh <<"EOF";
#ifndef OPENSSL_NO_${lib}
EOF
        $indent .= ' ';
    }

    print $fh "/*\n * $lib reason codes.\n */\n";
    foreach my $i ( @reasons ) {
        print $fh "#define $i $rcodes{$i}\n";
    }
    print $fh "\n";

    while (length($indent) > 0) {
        $indent = substr $indent, 0, -1;
        print $fh "#endif\n";
    }
}

# Write the C source file containing the error details for $lib
sub write_c_source
{
    my ( $lib, $fh ) = @_;
    my @reasons = reasons_of($lib);
    my $disablable = lib_disablable($lib);
    my $cfile = $errorfile{$lib};
    my $hpubincf = $hpubinc{$lib};
    my $hprivincf = $hprivinc{$lib};
    my $includes = '';

    if ($hpubincf ne 'NONE') {
        $hpubincf =~ s|^include/||;
        $includes .= "#include <${hpubincf}>\n";
    }
    if ($hprivincf =~ m|^include/|) {
        $hprivincf = $';
    } else {
        $hprivincf = abs2rel(rel2abs($hprivincf),
                             rel2abs(dirname($cfile)));
    }
    $includes .= "#include \"${hprivincf}\"\n";

    print $fh <<"EOF";
/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
$includes
EOF
    if ($disablable) {
        print $fh <<"EOF";
#ifndef OPENSSL_NO_${lib}

EOF
    }
    print $fh <<"EOF";
#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA ${lib}_str_reasons[] = {
EOF

    foreach my $i ( @reasons ) {
        my $lines;

        $lines = "    { ERR_PACK(ERR_LIB_${lib}, 0, $i), \"$strings{$i}\" },";
        $lines = "    { ERR_PACK(ERR_LIB_${lib}, 0, $i),\n        \"$strings{$i}\" },"
            if length($lines) > 82;
        print $fh "$lines\n";
    }
    print $fh <<"EOF";
    { 0, NULL }
};

#endif

int ossl_err_load_${lib}_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(${lib}_str_reasons[0].error) == NULL)
        ERR_load_strings_const(${lib}_str_reasons);
#endif
    return 1;
}
EOF

    if ($disablable) {
        print $fh <<"EOF";
#else
NON_EMPTY_TRANSLATION_UNIT
#endif
EOF
    }
}
