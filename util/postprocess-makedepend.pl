#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use lib '.';
use configdata;

use File::Spec::Functions qw(canonpath rel2abs);

my $abs_srcdir = rel2abs($config{sourcedir});
my $abs_blddir = rel2abs($config{builddir});

my $producer = shift @ARGV;
die "Producer not given\n" unless $producer;

my $procedure = {
    'makedepend' =>
        sub {
            my $line = shift;

            # makedepend, in its infinite wisdom, wants to have the object file
            # in the same directory as the source file.  This doesn't work too
            # well with out-of-source-tree builds, so we must resort to tricks
            # to get things right.  The trick is to call makedepend with an
            # extra suffix that contains the desired object file path, like
            # this:
            #
            #   makedepend -f- -o"|dir/foo.o" -- $(CFLAGS) -- ../some/foo.c
            #
            # The result will look something like this:
            #
            #   ../somewhere/foo|dir/foo.o: deps...
            #
            # Which is easy to massage by removing everything up to the first |

            # Remove everything up to the first |
            $line =~ s/^.*\|//;
            # Also, remove any dependency that starts with a /, because those
            # are typically system headers
            $line =~ s/\s+\/(\\.|\S)*//g;
            # Finally, discard all empty lines or comment lines
            return undef if $line =~ /:\s*$/ || $line =~ /^(#.*|\s*)$/;

            my ($target, $deps) = $line =~ /^((?:\\.|[^:])*):(.*)/;
            $deps =~ s/^\s+//;
            $deps =~ s/\s+$//;
            return ($target, $deps);
        },
    'VMS C' =>
        sub {
            my $line = shift;

            # current versions of DEC / Compaq / HP / VSI C strips away all
            # directory information from the object file, so we must insert it
            # back. Just to be safe against future changes, we check that there
            # really is no directory information.
            my $directory = shift;

            # The pattern for target and dependencies will always take this
            # form:
            #
            #   target SPACE : SPACE deps
            #
            # This is so a volume delimiter (a : without any spaces around it)
            # won't get mixed up with the target / deps delimiter.  We use this
            # fact in the regexp below to make sure we do look at the target.
            $line =~ s/^/$directory/ unless /^\S+[:>\]]\S+\s+:/;

            # We know that VMS has system header files in text libraries,
            # extension .TLB.  We also know that our header files aren't stored
            # in text libraries.  Finally, we know that VMS C produces exactly
            # one dependency per line, so we simply discard any line ending with
            # .TLB.
            return undef if /\.TLB\s*$/;

            my ($target, $deps) = $line =~ /^(.*)\s:\s(.*)/;
            $deps =~ s/^\s+//;
            $deps =~ s/\s+$//;
            return ($target, $deps);
        },
    'VC' =>
        sub {
            my $line = shift;
            my $object = shift;

            # For the moment, we only support Visual C on native Windows, or
            # compatible compilers.  With those, the flags /Zs /showIncludes
            # give us the necessary output to be able to create dependencies
            # that nmake (or any 'make' implementation) should be able to read,
            # with a bit of help.  The output we're interested in looks like
            # this (it always starts the same)
            #
            #   Note: including file: {whatever header file}
            #
            # So all we really have to do is to is to replace the start of the
            # line with an object file specification, given to us as an extra
            # argument (passed from $ARGV[1]);
            #
            # There are also other lines mixed in, for example compiler
            # warnings, so we simply discard anything that doesn't start with
            # the Note:

            if (/^Note: including file: */) {
                (my $tail = $') =~ s/\s*\R$//;

                # VC gives us absolute paths for all include files, so to
                # remove system header dependencies, we need to check that
                # they don't match $abs_srcdir or $abs_blddir
                $tail = canonpath($tail);
                if ($tail =~ m|^\Q$abs_srcdir\E|i
                        || $tail =~ m|^\Q$abs_blddir\E|i) {
                    return ($object, "\"$tail\"");
                }
            }

            return undef;
        },
} -> {$producer};

die "Producer unrecognised: $producer\n" unless defined $procedure;

my %collect = ();
while (<STDIN>) {
    s|\R$||;                    # The better chomp
    my ($target, $deps) = $procedure->($_, @ARGV);
    $collect{$target}->{$deps} = 1
        if defined $target;
}

my $continuation = {
    'makedepend' => "\\",
    'VMS C' => "-",
    'VC' => "\\",
} -> {$producer};

die "Producer unrecognised: $producer\n" unless defined $continuation;

foreach my $target (sort keys %collect) {
    my $prefix = $target . ' :';
    my @deps = sort keys %{$collect{$target}};

    while (@deps) {
        my $buf = $prefix;
        $prefix = '';

        while (@deps && ($buf eq '' || length($buf) + length($deps[0]) <= 77)) {
            $buf .= ' ' . shift @deps;
        }
        $buf .= ' '.$continuation if @deps;

        print $buf,"\n";
    }
}
