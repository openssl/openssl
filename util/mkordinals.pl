#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate an ordinals file from a symbol file and the ordinal and version
# assignments made by the last release.

use strict;
use warnings;

use Getopt::Long;

my $symbols_file = undef;       # the .sym file, authored
my $release_file = undef;       # the .release.num file, written at release
my $version = undef;            # version to stamp on unassigned symbols

GetOptions('symbols=s' => \$symbols_file,
           'release=s' => \$release_file,
           'version=s' => \$version)
    or die "Error in command line arguments\n";

die "Please supply --symbols\n" unless $symbols_file;
die "Please supply --release\n" unless $release_file;
die "Please supply --version\n" unless $version;

$version =~ s|\.|_|g;

# The symbol file.  Order is not significant here; the entries are keyed by
# name and emitted in the order the assignments give them.
my %symbols = ();
open my $sym, '<', $symbols_file or die "Unable to open $symbols_file: $!\n";
while (<$sym>) {
    s|#.*||;
    s|\R$||;
    next if /^\s*$/;

    my ($name, @rest) = split /\s+/;
    my $entry = { platforms => '', type => 'FUNCTION', features => '' };
    my $seen_features = 0;

    foreach (@rest) {
        if (m|^platform=(.*)$|) {
            $entry->{platforms} = $1;
        } elsif (m|^type=(.*)$|) {
            $entry->{type} = $1;
        } elsif ($seen_features) {
            die "$symbols_file:$.: more than one feature list for $name\n";
        } else {
            $entry->{features} = $_;
            $seen_features = 1;
        }
    }

    # A union merge keeps both sides, so a name can arrive twice.  A symbol
    # is listed once; the surplus line goes.
    die "$symbols_file:$.: $name is listed more than once\n"
        if exists $symbols{$name};

    $symbols{$name} = $entry;
}
close $sym;

# The assignments, in the order they are written, which is ascending by
# ordinal with the two names of an alias pair adjacent.
my @assigned = ();
my %assigned = ();
open my $rel, '<', $release_file or die "Unable to open $release_file: $!\n";
while (<$rel>) {
    s|#.*||;
    s|\R$||;
    next if /^\s*$/;

    my ($name, $ordinal, $relversion) = split /\s+/;
    die "$release_file:$.: malformed entry\n"
        unless defined $name && defined $ordinal && defined $relversion;
    die "$release_file:$.: $name assigned twice\n" if exists $assigned{$name};

    $assigned{$name} = 1;
    push @assigned, [ $name, $ordinal, $relversion ];
}
close $rel;

sub emit {
    my ($name, $ordinal, $ver, $exists, $entry) = @_;

    printf "%-39s %s\t%s\t%s:%s:%s:%s\n", $name, $ordinal, $ver,
        $exists ? 'EXIST' : 'NOEXIST',
        $entry->{platforms}, $entry->{type}, $entry->{features};
}

# Symbols the last release assigned.  One that the symbol file no longer
# lists has been removed; it stays here as NOEXIST so that its slot is not
# handed to anything else.
foreach (@assigned) {
    my ($name, $ordinal, $relversion) = @$_;
    my $entry = $symbols{$name};

    if (defined $entry) {
        emit($name, $ordinal, $relversion, 1, $entry);
    } else {
        emit($name, $ordinal, $relversion, 0,
             { platforms => '', type => 'FUNCTION', features => '' });
    }
}

# Symbols added since that release.  They have no ordinal until the next one
# assigns them, and '?' takes its value from the position of the line, so
# they are emitted last and in a fixed order.
foreach my $name (sort { $a cmp $b } grep { !exists $assigned{$_} }
                  keys %symbols) {
    emit($name, '?', $version, 1, $symbols{$name});
}
