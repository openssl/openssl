#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

my $producer = $ARGV[0];

while (<STDIN>) {
    if ($producer eq 'makedepend') {

        # makedepend, in its infinite wisdom, wants to have the object file in
        # the same directory as the source file.  This doesn't work too well
        # with out-of-source-tree builds, so we must resort to tricks to get
        # things right.  The trick is to call makedepend with an extra suffix
        # that contains the desired object file path, like this:
        #
        #     makedepend -f- -o"|dir/foo.o" -- $(CFLAGS) -- ../somewhere/foo.c
        #
        # The result will look something like this:
        #
        #     ../somewhere/foo|dir/foo.o: deps...
        #
        # Which is easy to massage by removing everything up to the first |

        # Remove everything up to the first |
        s/^.*\|//;
        # Also, remove any dependency that starts with a /, because those are
        # typically system headers
        s/ \/(\\.|[^ ])*//;
        # Finally, discard all empty lines or comment lines
        $_ = undef if (/: *$/ || /^(#.*| *)$/);
        $_.="\n" unless !defined($_) or /\R$/g;

    } elsif ($producer eq 'VMS C') {

        # current versions of DEC / Compaq / HP / VSI C strips away all
        # directory information from the object file, so we must insert it
        # back. Just to be safe against future changes, we check that there
        # really is no directory information.

        my $directory = $ARGV[1];

        # The pattern for target and dependencies will always take this form:
        #
        #     target SPACE : SPACE deps
        #
        # This is so a volume delimiter (a : without any spaces around it)
        # won't get mixed up with the target / deps delimiter.  We use this
        # fact in the regexp below to make sure we do look at the target.
        s/^/$directory/ unless /^\S+[:>\]]\S+\s+:/;

        # We know that VMS has system header files in text libraries,
        # extension .TLB.  We also know that our header files aren't stored
        # in text libraries.  Finally, we know that VMS C produces exactly
        # one dependency per line, so we simply discard any line ending with
        # .TLB.
        $_ = undef if /\.TLB\s*$/;

    } elsif ($producer eq 'VC') {

        # For the moment, we only know of one native Windows C compiler, and
        # that's Visual C.  With that compiler, the flags /Zs /showIncludes
        # give us the necessary output to be able to create dependencies that
        # nmake (or any 'make' implementation) should be able to read, with a
        # bit of help.  The output we're interested in looks like this (it
        # always starts the same)
        #
        #     Note: including file: {whatever header file}
        #
        # So all we really have to do is to is to replace the start of the line
        # with an object file specification, given to us as $ARGV[1].
        #
        # There are also other lines mixed in, for example compiler warnings,
        # so we simply discard anything that doesn't start with the Note:

        my $object = $ARGV[1];
        if (/^Note: including file: */) {
            $_ = "${object}: ".$';
        } else {
            $_ = undef;
        }

    } else {
        if ($producer) {
            die "Producer unrecognised: $producer\n";
        } else {
            die "Producer not given\n";
        }
    }
} continue {
    print or die "$!\n";
}
