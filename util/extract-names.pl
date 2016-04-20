#! /usr/bin/env perl
# Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


$/ = "";			# Eat a paragraph at once.
while(<STDIN>) {
    s|\R$||;
    s/\n/ /gm;
    if (/^=head1 /) {
	$name = 0;
    } elsif ($name) {
	if (/ - /) {
	    s/ - .*//;
	    s/,\s+/,/g;
	    s/\s+,/,/g;
	    s/^\s+//g;
	    s/\s+$//g;
	    s/\s/_/g;
	    push @words, split ',';
	}
    }
    if (/^=head1 *NAME *$/) {
	$name = 1;
    }
}

print join("\n", @words),"\n";

