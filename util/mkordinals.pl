#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate an ordinals file from a symbol file and the ordinal and version
# assignments made by the last release.
#
# With --allocate, assign ordinals and a version to the symbols that do not
# have them yet and write the result to --out, which is what a release does.

use strict;
use warnings;

use Getopt::Long;

my $symbols_file = undef;       # the .sym file, authored
my $release_file = undef;       # the .release.num file, written at release
my $version = undef;            # version to stamp on unassigned symbols
my $allocate = 0;               # assign, rather than generate the ordinals
my $out = undef;                # where --allocate writes

GetOptions('symbols=s' => \$symbols_file,
           'release=s' => \$release_file,
           'version=s' => \$version,
           'allocate'  => \$allocate,
           'out=s'     => \$out)
    or die "Error in command line arguments\n";

die "Please supply --symbols\n" unless $symbols_file;
die "Please supply --release\n" unless $release_file;
die "Please supply --version\n" unless $version;
die "Please supply --out with --allocate\n" if $allocate && !defined $out;

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

# The symbols with no ordinal, in the order they are given one.  A '?' takes
# its value from the position of its line, so this order decides both the
# generated file and the assignment a release makes, and has to be the same
# in each.  The symbol file has no order to inherit.
my @unassigned = sort { $a cmp $b } grep { !exists $assigned{$_} } keys %symbols;

# A release assigns the ordinals and version that were pending.  Everything
# already assigned keeps what it has, including a symbol that has since been
# removed, whose slot stays spent.
if ($allocate) {
    my $next = 0;

    foreach (@assigned) {
        $next = $_->[1] if $_->[1] > $next;
    }

    open my $fh, '>', $out or die "Unable to open $out: $!\n";
    print $fh <<"_____";
# Ordinal and version assignments, written by the release
# process.  Do not edit by hand.
#
# The ordinal is the VMS symbol vector slot and the version
# is the ELF version node; both are fixed for the life of a
# major release.  A symbol listed here but absent from the
# .sym file has been removed, and keeps its slot so that
# nothing else is given it.

_____
    foreach (@assigned) {
        printf $fh "%-39s %s\t%s\n", @$_;
    }
    foreach my $name (@unassigned) {
        printf $fh "%-39s %s\t%s\n", $name, ++$next, $version;
    }
    close $fh;
    exit 0;
}

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

# Symbols added since that release, which have no ordinal until the next one
# assigns them.
foreach my $name (@unassigned) {
    emit($name, '?', $version, 1, $symbols{$name});
}
