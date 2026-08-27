#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

sub rename_labels {
    my ($text, $from, $to) = @_;
    my %labels;

    while ($text =~ /^\s*([A-Za-z_.][A-Za-z0-9_\$.]*):/mg) {
        my ($label, $replacement) = ($1, $1);

        $replacement .= "_p12" unless $replacement =~ s/\Q$from\E/$to/g;
        $labels{$label} = $replacement;
    }

    if (%labels) {
        my $pattern = join("|", map { quotemeta($_) }
                                sort { length($b) <=> length($a) }
                                keys %labels);

        $text =~ s/(?<![A-Za-z0-9_\$.])($pattern)(?![A-Za-z0-9_\$.])/$labels{$1}/g;
    }

    return $text;
}

1;
