#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Add new copyright and delete old ones.  Used as
#   find . -name '*.[ch]' -type f -exec perl -i.bak util/copyright.pl '{}' ';'
# This does not do everything that's needed for the consolidation.

use strict;
use warnings;

# Read a multi-line comments.  If it matches a "fingerprint" of a legacy
# copyright block, then just delete it.
sub check_comment()
{
    my @lines = ( @_ );
    my $skipit = 0;

    if ($lines[$#lines] !~ m@\*/@) {
        while ( <> ) {
            push @lines, $_;
            last if m@\*/@;
            $skipit = 1 if /Copyright remains Eric Young's/i;
            $skipit = 1 if /Copyright.*The OpenSSL Project/i;
            $skipit = 1 if /Written by.*for the OpenSSL Project/i;
        }
    }

    # Look for a multi-line "written by" comment.
    if ( ! $skipit ) {
        my $text = join('', @lines);
        $skipit = 1 if $text =~ m/Written by.*for the OpenSSL Project/is;
    }

    print @lines unless $skipit;
    return $skipit;
}

# Look for leading copyright blocks and process (print/swallow) them.
while ( <> ) {
    if ($. == 1) {
        my $DATE;
        # Look for special copyright EAY line at line one.
        if ( /Copyright.*(199.)-.*Eric Young/ ) {
            $DATE = $1;
        } else {
            # Nope, use when it first existed in git.
            $DATE=`git log '--pretty=format:%cI' $ARGV | tail -1`;
            $DATE =~ s/-.*//;
        }
        my $YEAR = $DATE ? $DATE : 1995;
        my $SPAN = $YEAR == 2016 ? "2016" : "${YEAR}-2016";
        print <<EOF;
/*
 * Copyright ${SPAN} The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

EOF
    }
    next if m@^$@;
    last if not m@/\*@;
    last unless &check_comment($_);
}

if (defined($_)) {
    print unless m@\*/@;

    # Print rest of file.
    print while ( <> );
}
