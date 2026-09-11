#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# One-shot extractor: parse the _EC_* blocks and curve_list[] entries in
# crypto/ec/ec_curve.c, and emit crypto/ec/ec_curves.conf (a config-target
# style Perl data file whose last expression is the curve table).
#
# The data file's curve key is the name that, sanitized with s/-/_/g,
# gives the NID macro suffix.  For curves with multiple names, we pick
# the one that maps cleanly; the comment records the alternate name(s).

use strict;
use warnings;

my $curve_c = 'crypto/ec/ec_curve.c';
my $objects_txt = 'crypto/objects/objects.txt';
my $out_file = 'crypto/ec/ec_curves.conf';

# ------------------------------------------------------------------
# Parse objects.txt for name -> NID and NID -> names
# ------------------------------------------------------------------
my %nid_for_name;   # name -> NID
my %names_for_nid;  # NID -> [name, ...]

open my $obj_fh, '<', $objects_txt
    or die "Cannot open $objects_txt: $!\n";
while (<$obj_fh>) {
    chomp;
    s/#.*$//;
    next if /^\s*$/;
    # Format: <oid> <extra> : <SN> : <LN>
    # We only care about the name parts
    my @parts = split /\s*:\s*/;
    next unless @parts >= 2;
    my ($sn, $ln) = @parts[1, 2];
    # The OID part may contain the NID number after the OID.
    # We don't need it here; we only need the names for the comment.
}
close $obj_fh;

# ------------------------------------------------------------------
# Parse ec_curve.c for _EC_* blocks and curve_list[] entries
# ------------------------------------------------------------------
open my $fh, '<', $curve_c or die "Cannot open $curve_c: $!\n";

my @blocks;          # parsed _EC_* blocks
my @list_entries;    # (nid, block_name, guards, fips)

my $in_block = 0;
my $cur = undef;
my $in_list = 0;
my @guard_stack;     # stack of {directive, in_else}
my $list_fips = 0;

while (<$fh>) {
    chomp;
    my $line = $_;

    # Preprocessor guards
    if (/^\s*#\s*(ifn?def|if|else|endif)\b\s*(.*)/) {
        my ($kind, $rest) = ($1, $2);
        $rest =~ s/\s+$//;
        if ($kind eq 'if' || $kind eq 'ifdef' || $kind eq 'ifndef') {
            push @guard_stack, { directive => "#$kind $rest", in_else => 0 };
        } elsif ($kind eq 'else') {
            $guard_stack[-1]{in_else} = 1;
        } else {
            pop @guard_stack;
        }
        next;
    }

    # _EC_* block start
    if (!$in_block && /^\}\s+(_EC_\w+)\s*=\s*\{/) {
        $in_block = 1;
        $cur = { name => $1, guards => [map { { %$_ } } @guard_stack],
                 bytes => [], header_seen => 0 };
        next;
    }

    if ($in_block) {
        if (!$cur->{header_seen}) {
            if (/^\s*\{\s*(NID_\w+),\s*(\d+),\s*(\d+),\s*(0x[0-9A-Fa-f]+|\d+)\s*\},/) {
                $cur->{field_type} = $1;
                $cur->{seed_len}   = $2;
                $cur->{param_len}  = $3;
                $cur->{cofactor}   = $4;
                $cur->{header_seen} = 1;
            }
            next;
        }
        if (/^\s*\};/) {
            push @blocks, $cur;
            $in_block = 0;
            $cur = undef;
            next;
        }
        # Accumulate hex bytes
        while (/0x([0-9A-Fa-f]{1,2})/g) {
            push @{$cur->{bytes}}, hex($1);
        }
        next;
    }

    # curve_list[] entries
    if (/^\s*static const ec_list_element curve_list\[\] = \{/) {
        $in_list = 1;
        $list_fips = grep { $_->{directive} =~ /FIPS_MODULE/ && $_->{directive} !~ /ifndef/ && !$_->{in_else} } @guard_stack;
        next;
    }
    if ($in_list) {
        if (/^\s*\};\s*$/) {
            $in_list = 0;
            next;
        }
        if (/^\s*\{\s*(NID_\w+),\s*&(_EC_\w+)\.h,/) {
            my ($nid, $blk) = ($1, $2);
            push @list_entries, {
                nid    => $nid,
                block  => $blk,
                guards => [map { { %$_ } } @guard_stack],
                fips   => $list_fips,
            };
        }
        next;
    }
}
close $fh;

# ------------------------------------------------------------------
# Build the output table
# ------------------------------------------------------------------

# Map NID -> block, and NID -> fips flag
my %nid_block;
my %nid_fips;
for my $e (@list_entries) {
    $nid_block{$e->{nid}} = $e->{block};
    $nid_fips{$e->{nid}} = 1 if $e->{fips};
}

# Map block -> primary NID (first non-FIPS reference)
my %block_nid;
for my $e (@list_entries) {
    next if $e->{fips};
    $block_nid{$e->{block}} //= $e->{nid};
}
# Fall back to FIPS for blocks only in the FIPS list
for my $e (@list_entries) {
    $block_nid{$e->{block}} //= $e->{nid};
}

# Name for NID macro: strip NID_ prefix
sub nid_name {
    my ($nid) = @_;
    $nid =~ s/^NID_//;
    return $nid;
}

# Sanitize a name to a C identifier (same as objects.pl)
sub sanitize {
    my ($name) = @_;
    $name =~ s/-/_/g;
    $name =~ s/\./_/g;
    return $name;
}

# Special cases: NID -> canonical name (the one that sanitizes to the NID suffix)
my %canonical_name = (
    'NID_ipsec3' => 'ipsec3',       # also known as Oakley-EC2N-3
    'NID_ipsec4' => 'ipsec4',       # also known as Oakley-EC2N-4
);

# Alternate names for comments
my %alt_names = (
    'ipsec3' => 'Oakley-EC2N-3',
    'ipsec4' => 'Oakley-EC2N-4',
);

# ------------------------------------------------------------------
# Emit the data file
# ------------------------------------------------------------------
open my $out, '>', $out_file or die "Cannot write $out_file: $!\n";

print $out <<'HEADER';
## -*- mode: perl; -*-
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# EC named-curve parameters, source of truth for static OSSL_FN backing.
# Ingested like Configurations/*.conf: the file's last expression is the
# table itself.  The curve key is the name that, sanitized with s/-/_/g,
# gives the NID macro suffix.  Values are big-endian hex strings.

HEADER

print $out "(\n";

for my $b (@blocks) {
    my $nid = $block_nid{$b->{name}};
    next unless defined $nid;

    my $name = $canonical_name{$nid} // nid_name($nid);
    my $cname = sanitize($name);

    # Extract field values from the byte array
    my $seed = $b->{seed_len};
    my $plen = $b->{param_len};
    my @data = @{$b->{bytes}};
    my @fields = ('p', 'a', 'b', 'x', 'y', 'order');
    my %vals;
    for my $i (0 .. $#fields) {
        my @chunk = @data[$seed + $i * $plen .. $seed + ($i + 1) * $plen - 1];
        $vals{$fields[$i]} = join '', map { sprintf '%02X', $_ } @chunk;
    }

    # Determine field type
    my $field = ($b->{field_type} eq 'NID_X9_62_characteristic_two_field')
        ? 'char2' : 'prime';

    # Determine FIPS flag
    my $fips = $nid_fips{$nid} ? 1 : 0;

    # Determine enabled coderef from guards
    my @enabled_conds;
    for my $g (@{$b->{guards}}) {
        my $d = $g->{directive};
        if ($d =~ /ifndef OPENSSL_NO_EC2M/) {
            push @enabled_conds, "!disabled('ec2m')";
        }
        if ($d =~ /ifndef OPENSSL_NO_SM2/) {
            push @enabled_conds, "!disabled('sm2')";
        }
    }
    # FIPS-only curves (no non-FIPS list entry) are not in the static table
    # at all; non-FIPS curves that are also in the FIPS list get fips => 1.
    # We don't emit an enabled condition for FIPS_MODULE exclusion because
    # that's handled by the table lookup at runtime (the curve_list[]
    # fallback still works).

    my $comment = '';
    if (exists $alt_names{$name}) {
        $comment = " # also known as $alt_names{$name}";
    }

    print $out " '$name' => {$comment\n";
    print $out "     field     => '$field',\n";
    print $out "     param_len => $plen,\n";
    print $out "     cofactor  => $b->{cofactor},\n";
    if ($seed > 0) {
        my $seed_hex = join '', map { sprintf '%02X', $_ } @data[0 .. $seed - 1];
        print $out "     seed      => '$seed_hex',\n";
    }
    for my $f (@fields) {
        print $out "     $f" . (' ' x (7 - length $f)) . "=> '$vals{$f}',\n";
    }
    print $out "     fips      => $fips,\n" if $fips;
    if (@enabled_conds) {
        my $cond = join ' && ', @enabled_conds;
        print $out "     enabled   => sub { $cond },\n";
    }
    print $out " },\n";
    print $out "\n";
}

print $out ");\n";
close $out;

printf STDERR "Wrote %s: %d curves\n", $out_file, scalar grep { defined $block_nid{$_->{name}} } @blocks;
