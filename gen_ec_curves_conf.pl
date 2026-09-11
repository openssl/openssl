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
# NIDs that share their parameter block with another curve become alias
# records (alias_of).

use strict;
use warnings;

my $curve_c = $ARGV[0] // 'crypto/ec/ec_curve.c';
my $out_file = 'crypto/ec/ec_curves.conf';

# ------------------------------------------------------------------
# Parse ec_curve.c for _EC_* blocks and curve_list[] entries
# ------------------------------------------------------------------
open my $fh, '<', $curve_c or die "Cannot open $curve_c: $!\n";

my @blocks;          # parsed _EC_* blocks
my @list_entries;    # {nid, block, text, fips}

my $in_block = 0;
my $cur = undef;
my $in_list = 0;
my @guard_stack;
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
        while (/0x([0-9A-Fa-f]{1,2})/g) {
            push @{$cur->{bytes}}, hex($1);
        }
        next;
    }

    # curve_list[] tables
    if (/^\s*static const ec_list_element curve_list\[\] = \{/) {
        $in_list = 1;
        $list_fips = grep { $_->{directive} =~ /FIPS_MODULE/
                                && $_->{directive} !~ /ifndef/
                                && !$_->{in_else} } @guard_stack;
        next;
    }
    if ($in_list) {
        if (/^\s*\};\s*$/) {
            $in_list = 0;
            next;
        }
        if (/^\s*\{\s*(NID_\w+),\s*&(_EC_\w+)\.h,/) {
            # Capture the whole entry, through the closing "},"
            my $entry = { nid => $1, block => $2, fips => $list_fips,
                          text => $line };
            while (<$fh>) {
                $entry->{text} .= $_;
                last if /\},/;
            }
            push @list_entries, $entry;
        }
        next;
    }
}
close $fh;

# ------------------------------------------------------------------
# Analyze
# ------------------------------------------------------------------

# block -> parsed block data
my %block_by_name = map { $_->{name} => $_ } @blocks;

# Method name from the method functions mentioned in the entry text
my %method_of_func = (
    EC_GFp_nistp224_method       => 'nistp224',
    EC_GFp_nistz256_method       => 'nistz256',
    EC_GFp_s390x_nistp256_method => 'nistz256',
    EC_GFp_nistp256_method       => 'nistz256',
    EC_GFp_s390x_nistp384_method => 'nistp384',
    ossl_ec_GFp_nistp384_method  => 'nistp384',
    EC_GFp_s390x_nistp521_method => 'nistp521',
    EC_GFp_nistp521_method       => 'nistp521',
    EC_GFp_sm2p256_method        => 'sm2p256',
);

sub entry_method {
    my ($text) = @_;
    for my $func (keys %method_of_func) {
        return $method_of_func{$func} if $text =~ /\b\Q$func\E\b/;
    }
    return undef;
}

# Comment from the entry text: concatenate the C string literals
sub entry_comment {
    my ($text) = @_;
    my $comment = '';
    while ($text =~ /"((?:[^"\\]|\\.)*)"/gs) {
        $comment .= $1;
    }
    return $comment;
}

# Split entries into the non-FIPS list and the FIPS list
my @nonfips_entries = grep { !$_->{fips} } @list_entries;
my @fips_entries    = grep { $_->{fips} } @list_entries;

# FIPS availability per nid
my %nid_fips = map { $_->{nid} => 1 } @fips_entries;

# Primary NID per block: the first non-FIPS entry referencing it
my %block_primary;
for my $e (@nonfips_entries) {
    $block_primary{$e->{block}} //= $e->{nid};
}

# De-duplicate non-FIPS entries per nid (a nid may appear twice with
# method/no-method variants); prefer the entry with a method
my %best_entry;
for my $e (@nonfips_entries) {
    my $nid = $e->{nid};
    if (!exists $best_entry{$nid}
        || (!entry_method($best_entry{$nid}{text}) && entry_method($e->{text}))) {
        $best_entry{$nid} = $e;
    }
}

# Sanitize a name to a C identifier (same as objects.pl)
sub sanitize {
    my ($name) = @_;
    $name =~ s/-/_/g;
    $name =~ s/\./_/g;
    return $name;
}

sub nid_name {
    my ($nid) = @_;
    $nid =~ s/^NID_//;
    return $nid;
}

# Special cases: NID -> canonical name (the one that sanitizes to the
# NID suffix)
my %canonical_name = (
    'NID_ipsec3' => 'ipsec3',       # also known as Oakley-EC2N-3
    'NID_ipsec4' => 'ipsec4',       # also known as Oakley-EC2N-4
);
my %alt_names = (
    'ipsec3' => 'Oakley-EC2N-3',
    'ipsec4' => 'Oakley-EC2N-4',
);

# ------------------------------------------------------------------
# Emit the data file, in non-FIPS curve_list order
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

# EC named-curve parameters, source of truth for generated curve data.
# Ingested like Configurations/*.conf: the file's last expression is the
# table itself, a list of name => record pairs in curve_list order.  The
# curve key is the name that, sanitized with s/-/_/g, gives the NID macro
# suffix.  Values are big-endian hex strings.  Curves sharing their
# parameters with another curve are alias records (alias_of).

HEADER

print $out "(\n";

my %emitted;
for my $e (@nonfips_entries) {
    my $nid = $e->{nid};
    next if $emitted{$nid}++;
    $e = $best_entry{$nid};

    my $block = $block_by_name{$e->{block}};
    my $primary = $block_primary{$e->{block}};
    my $is_alias = $nid ne $primary;
    my $name = $canonical_name{$nid} // nid_name($nid);
    my $comment = entry_comment($e->{text});
    # Keep C escape sequences intact through the Perl round-trip
    $comment =~ s/\\/\\\\/g;
    my $alt = exists $alt_names{$name} ? " # also known as $alt_names{$name}" : '';

    print $out " '$name' => {$alt\n";

    if ($is_alias) {
        my $canonical = $canonical_name{$primary} // nid_name($primary);
        print $out "     alias_of  => '$canonical',\n";
        print $out "     comment   => \"$comment\",\n";
        print $out " },\n\n";
        next;
    }

    my $field = ($block->{field_type} eq 'NID_X9_62_characteristic_two_field')
        ? 'char2' : 'prime';
    my $seed = $block->{seed_len};
    my $plen = $block->{param_len};
    my @data = @{$block->{bytes}};
    my @fields = ('p', 'a', 'b', 'x', 'y', 'order');
    my %vals;
    for my $i (0 .. $#fields) {
        my @chunk = @data[$seed + $i * $plen .. $seed + ($i + 1) * $plen - 1];
        $vals{$fields[$i]} = join '', map { sprintf '%02X', $_ } @chunk;
    }
    # Any trailing data beyond the six parameters (e.g. the Montgomery RR
    # values for nistz256), in param_len-sized chunks
    my @extra;
    for (my $off = $seed + 6 * $plen; $off < @data; $off += $plen) {
        push @extra, join '', map { sprintf '%02X', $_ }
            @data[$off .. $off + $plen - 1];
    }

    # Guards -> enabled coderef
    my @enabled_conds;
    for my $g (@{$block->{guards}}) {
        my $d = $g->{directive};
        push @enabled_conds, "!disabled('ec2m')" if $d =~ /ifndef OPENSSL_NO_EC2M/;
        push @enabled_conds, "!disabled('sm2')"
            if $d =~ /ifndef OPENSSL_NO_SM2/ || $d =~ /!defined\(OPENSSL_NO_SM2\)/;
    }

    print $out "     field     => '$field',\n";
    print $out "     param_len => $plen,\n";
    print $out "     cofactor  => $block->{cofactor},\n";
    if ($seed > 0) {
        my $seed_hex = join '', map { sprintf '%02X', $_ } @data[0 .. $seed - 1];
        print $out "     seed      => '$seed_hex',\n";
    }
    for my $f (@fields) {
        print $out "     $f" . (' ' x (7 - length $f)) . "=> '$vals{$f}',\n";
    }
    if (@extra) {
        print $out "     extra     => ['" . join("', '", @extra) . "'],\n";
    }
    print $out "     fips      => 1,\n" if $nid_fips{$nid};
    if (my $m = entry_method($e->{text})) {
        print $out "     method    => '$m',\n";
    }
    if (@enabled_conds) {
        my $cond = join ' && ', @enabled_conds;
        print $out "     enabled   => sub { $cond },\n";
    }
    print $out "     comment   => \"$comment\",\n";
    print $out " },\n\n";
}

print $out ");\n";
close $out;

printf STDERR "Wrote %s: %d records\n", $out_file, scalar keys %emitted;
