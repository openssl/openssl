#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package OpenSSL::Ordinals;

use strict;
use warnings;
use Carp;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.1";
@ISA = qw(Exporter);
@EXPORT = qw(cmp_versions);
@EXPORT_OK = qw();

=head1 NAME

OpenSSL::Util - small OpenSSL utilities

=head1 SYNOPSIS

  use OpenSSL::Util;

  $versiondiff = cmp_versions('1.0.2k', '3.0.1');
  # $versiondiff should be -1

  $versiondiff = cmp_versions('1.1.0', '1.0.2a');
  # $versiondiff should be 1

  $versiondiff = cmp_versions('1.1.1', '1.1.1');
  # $versiondiff should be 0

=head1 DESCRIPTION

=over

=item B<cmp_versions "VERSION1", "VERSION2">

Compares VERSION1 with VERSION2, paying attention to OpenSSL versioning.

Returns 1 if VERSION1 is greater than VERSION2, 0 if they are equal, and
-1 if VERSION1 is less than VERSION2.

=back

=cut

# Until we're rid of everything with the old version scheme,
# we need to be able to handle older style x.y.zl versions.
# In terms of comparison, the x.y.zl and the x.y.z schemes
# are compatible...  mostly because the latter starts at a
# new major release with a new major number.
sub _ossl_versionsplit {
    my $textversion = shift;
    return $textversion if $textversion eq '*';
    my ($major,$minor,$edit,$letter) =
        $textversion =~ /^(\d+)\.(\d+)\.(\d+)([a-z]{0,2})$/;

    return ($major,$minor,$edit,$letter);
}

sub cmp_versions {
    my @a_split = _ossl_versionsplit(shift);
    my @b_split = _ossl_versionsplit(shift);
    my $verdict = 0;

    while (@a_split) {
        # The last part is a letter sequence (or a '*')
        if (scalar @a_split == 1) {
            $verdict = $a_split[0] cmp $b_split[0];
        } else {
            $verdict = $a_split[0] <=> $b_split[0];
        }
        shift @a_split;
        shift @b_split;
        last unless $verdict == 0;
    }

    return $verdict;
}

1;
