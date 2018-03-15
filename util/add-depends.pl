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
use File::Compare qw(compare_text);

# When using stat() on Windows, we can get it to perform better by avoid some
# data.  This doesn't affect the mtime field, so we're not losing anything...
${^WIN32_SLOPPY_STAT} = 1;

my $debug = $ENV{ADD_DEPENDS_DEBUG};
my $buildfile = $config{build_file};
my $build_mtime = (stat($buildfile))[9];
my $rebuild = 0;
my $depext = $target{dep_extension} || ".d";
my @depfiles =
    sort
    grep {
        # This grep has side effects.  Not only does if check the existence
        # of the dependency file given in $_, but it also checks if it's
        # newer than the build file, and if it is, sets $rebuild.
        my @st = stat($_);
        $rebuild = 1 if @st && $st[9] > $build_mtime;
        scalar @st > 0;         # Determines the grep result
    }
    map { (my $x = $_) =~ s|\.o$|$depext|; $x; }
    grep { $unified_info{sources}->{$_}->[0] =~ /\.cc?$/ }
    keys %{$unified_info{sources}};

exit 0 unless $rebuild;

# Ok, primary checks are done, time to do some real work

my $abs_srcdir = rel2abs($config{sourcedir});
my $abs_blddir = rel2abs($config{builddir});

my $producer = shift @ARGV;
die "Producer not given\n" unless $producer;

my %procedures = (
    'gcc' => undef,             # gcc style dependency files needs no mods
    'makedepend' =>
        sub {
            # makedepend, in its infinite wisdom, wants to have the object file
            # in the same directory as the source file.  This doesn't work too
            # well with out-of-source-tree builds, so we must resort to tricks
            # to get things right.  Fortunately, the .d files are always placed
            # parallel with the object files, so all we need to do is construct
            # the object file name from the dep file name.
            (my $objfile = shift) =~ s|\.d$|.o|i;
            my $line = shift;

            # Discard comments
            return undef if $line =~ /^(#.*|\s*)$/;

            # Remove the original object file
            $line =~ s|^.*\.o: | |;
            # Also, remove any dependency that starts with a /, because those
            # are typically system headers
            $line =~ s/\s+\/(\\.|\S)*//g;
            # Finally, discard all empty lines
            return undef if $line =~ /^\s*$/;

            # All we got now is a dependency, just shave off surrounding spaces
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
            return ($objfile, $line);
        },
    'VMS C' =>
        sub {
            # current versions of DEC / Compaq / HP / VSI C strips away all
            # directory information from the object file, so we must insert it
            # back.  To make life simpler, we simply replace it with the
            # corresponding .D file that's had its extension changed.  Since
            # .D files are always written parallel to the object files, we
            # thereby get the directory information for free.
            (my $objfile = shift) =~ s|\.D$|.OBJ|i;
            my $line = shift;

            # Shave off the target.
            #
            # The pattern for target and dependencies will always take this
            # form:
            #
            #   target SPACE : SPACE deps
            #
            # This is so a volume delimiter (a : without any spaces around it)
            # won't get mixed up with the target / deps delimiter.  We use this
            # to easily identify what needs to be removed.
            m|\s:\s|; $line = $';

            # We know that VMS has system header files in text libraries,
            # extension .TLB.  We also know that our header files aren't stored
            # in text libraries.  Finally, we know that VMS C produces exactly
            # one dependency per line, so we simply discard any line ending with
            # .TLB.
            return undef if /\.TLB\s*$/;

            # All we got now is a dependency, just shave off surrounding spaces
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
            return ($objfile, $line);
        },
    'VC' =>
        sub {
            # For the moment, we only support Visual C on native Windows, or
            # compatible compilers.  With those, the flags /Zs /showIncludes
            # give us the necessary output to be able to create dependencies
            # that nmake (or any 'make' implementation) should be able to read,
            # with a bit of help.  The output we're interested in looks like
            # this (it always starts the same)
            #
            #   Note: including file: {whatever header file}
            #
            # Since there's no object file name at all in that information,
            # we must construct it ourselves.

            (my $objfile = shift) =~ s|\.d$|.obj|i;
            my $line = shift;

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
                    return ($objfile, "\"$tail\"");
                }
            }

            return undef;
        },
);
my %continuations = (
    'gcc' => undef,
    'makedepend' => "\\",
    'VMS C' => "-",
    'VC' => "\\",
);

die "Producer unrecognised: $producer\n"
    unless exists $procedures{$producer} && exists $continuations{$producer};

my $procedure = $procedures{$producer};
my $continuation = $continuations{$producer};

my $buildfile_new = "$buildfile-$$";

my %collect = ();
if (defined $procedure) {
    foreach my $depfile (@depfiles) {
        open IDEP,$depfile or die "Trying to read $depfile: $!\n";
        while (<IDEP>) {
            s|\R$||;                # The better chomp
            my ($target, $deps) = $procedure->($depfile, $_);
            $collect{$target}->{$deps} = 1 if defined $target;
        }
        close IDEP;
    }
}

open IBF, $buildfile or die "Trying to read $buildfile: $!\n";
open OBF, '>', $buildfile_new or die "Trying to write $buildfile_new: $!\n";
while (<IBF>) {
    last if /^# DO NOT DELETE THIS LINE/;
    print OBF or die "$!\n";
}
close IBF;

print OBF "# DO NOT DELETE THIS LINE -- make depend depends on it.\n";

if (defined $procedure) {
    foreach my $target (sort keys %collect) {
        my $prefix = $target . ' :';
        my @deps = sort keys %{$collect{$target}};

        while (@deps) {
            my $buf = $prefix;
            $prefix = '';

            while (@deps && ($buf eq ''
                                 || length($buf) + length($deps[0]) <= 77)) {
                $buf .= ' ' . shift @deps;
            }
            $buf .= ' '.$continuation if @deps;

            print OBF $buf,"\n" or die "Trying to print: $!\n"
        }
    }
} else {
    foreach my $depfile (@depfiles) {
        open IDEP,$depfile or die "Trying to read $depfile: $!\n";
        while (<IDEP>) {
            print OBF or die "Trying to print: $!\n";
        }
        close IDEP;
    }
}

close OBF;

if (compare_text($buildfile_new, $buildfile) != 0) {
    rename $buildfile_new, $buildfile
        or die "Trying to rename $buildfile_new -> $buildfile: $!\n";
}

END {
    # On VMS, we want to remove all generations of this file, in case there
    # are more than one, so we loop.
    if (defined $buildfile_new) {
        while (unlink $buildfile_new) {}
    }
}
