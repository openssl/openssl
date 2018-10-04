#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate a linker version script suitable for the given platform
# from a given ordinals file.

use strict;
use warnings;

use Getopt::Long;
use FindBin;
use lib "$FindBin::Bin/perl";

use OpenSSL::Ordinals;

use lib '.';
use configdata;

my $name = undef;               # internal library/module name
my $ordinals_file = undef;      # the ordinals file to use
my $OS = undef;                 # the operating system family
my $verbose = 0;
my $ctest = 0;

GetOptions('name=s'     => \$name,
           'ordinals=s' => \$ordinals_file,
           'OS=s'       => \$OS,
           'ctest'      => \$ctest,
           'verbose'    => \$verbose)
    or die "Error in command line arguments\n";

die "Please supply arguments\n"
    unless $name && $ordinals_file && $OS;

# When building a "variant" shared library, with a custom SONAME, also customize
# all the symbol versions.  This produces a shared object that can coexist
# without conflict in the same address space as a default build, or an object
# with a different variant tag.
#
# For example, with a target definition that includes:
#
#         shlib_variant => "-opt",
#
# we build the following objects:
#
# $ perl -le '
#     for (@ARGV) {
#         if ($l = readlink) {
#             printf "%s -> %s\n", $_, $l
#         } else {
#             print
#         }
#     }' *.so*
# libcrypto-opt.so.1.1
# libcrypto.so -> libcrypto-opt.so.1.1
# libssl-opt.so.1.1
# libssl.so -> libssl-opt.so.1.1
#
# whose SONAMEs and dependencies are:
#
# $ for l in *.so; do
#     echo $l
#     readelf -d $l | egrep 'SONAME|NEEDED.*(ssl|crypto)'
#   done
# libcrypto.so
#  0x000000000000000e (SONAME)             Library soname: [libcrypto-opt.so.1.1]
# libssl.so
#  0x0000000000000001 (NEEDED)             Shared library: [libcrypto-opt.so.1.1]
#  0x000000000000000e (SONAME)             Library soname: [libssl-opt.so.1.1]
#
# We case-fold the variant tag to upper case and replace all non-alnum
# characters with "_".  This yields the following symbol versions:
#
# $ nm libcrypto.so | grep -w A
# 0000000000000000 A OPENSSL_OPT_1_1_0
# 0000000000000000 A OPENSSL_OPT_1_1_0a
# 0000000000000000 A OPENSSL_OPT_1_1_0c
# 0000000000000000 A OPENSSL_OPT_1_1_0d
# 0000000000000000 A OPENSSL_OPT_1_1_0f
# 0000000000000000 A OPENSSL_OPT_1_1_0g
# $ nm libssl.so | grep -w A
# 0000000000000000 A OPENSSL_OPT_1_1_0
# 0000000000000000 A OPENSSL_OPT_1_1_0d
#
(my $SO_VARIANT = uc($target{"shlib_variant"} // '')) =~ s/\W/_/g;

my $apiv = undef;
$apiv = sprintf "%x%02x%02x", split(/\./, $config{api})
    if $config{api};

my $libname = $unified_info{sharednames}->{$name} // $name;

my %OS_data = (
    solaris     => { writer     => \&writer_linux,
                     sort       => sorter_linux(),
                     platforms  => { UNIX                       => 1,
                                     EXPORT_VAR_AS_FUNCTION     => 0 } },
    linux       => 'solaris',   # alias
    aix         => { writer     => \&writer_aix,
                     sort       => sorter_unix(),
                     platforms  => { UNIX                       => 1,
                                     EXPORT_VAR_AS_FUNCTION     => 0 } },
    VMS         => { writer     => \&writer_VMS,
                     sort       => OpenSSL::Ordinals::by_number(),
                     platforms  => { VMS                        => 1,
                                     EXPORT_VAR_AS_FUNCTION     => 0 } },
    vms         => 'VMS',       # alias
    WINDOWS     => { writer     => \&writer_windows,
                     sort       => OpenSSL::Ordinals::by_name(),
                     platforms  => { WIN32                      => 1,
                                     _WIN32                     => 1,
                                     EXPORT_VAR_AS_FUNCTION     => 1 } },
    windows     => 'WINDOWS',   # alias
    WIN32       => 'WINDOWS',   # alias
    win32       => 'WIN32',     # alias
    32          => 'WIN32',     # alias
    NT          => 'WIN32',     # alias
    nt          => 'WIN32',     # alias
    mingw       => 'WINDOWS',   # alias
   );

do {
    die "Unknown operating system family $OS\n"
        unless exists $OS_data{$OS};
    $OS = $OS_data{$OS};
} while(ref($OS) eq '');

my %disabled_uc = map { my $x = uc $_; $x =~ s|-|_|g; $x => 1 } keys %disabled;

my %ordinal_opts = ();
$ordinal_opts{sort} = $OS->{sort} if $OS->{sort};
$ordinal_opts{filter} =
    sub {
        my $item = shift;
        return
            $item->exists()
            && platform_filter($item)
            && feature_filter($item);
    };
my $ordinals = OpenSSL::Ordinals->new(from => $ordinals_file);

my $writer = $OS->{writer};
$writer = \&writer_ctest if $ctest;

$writer->($ordinals->items(%ordinal_opts));

exit 0;

sub platform_filter {
    my $item = shift;
    my %platforms = ( $item->platforms() );

    # True if no platforms are defined
    return 1 if scalar keys %platforms == 0;

    # For any item platform tag, return the equivalence with the
    # current platform settings if it exists there, return 0 otherwise
    # if the item platform tag is true
    for (keys %platforms) {
        if (exists $OS->{platforms}->{$_}) {
            return $platforms{$_} == $OS->{platforms}->{$_};
        }
        if ($platforms{$_}) {
            return 0;
        }
    }

    # Found no match?  Then it's a go
    return 1;
}

sub feature_filter {
    my $item = shift;
    my @features = ( $item->features() );

    # True if no features are defined
    return 1 if scalar @features == 0;

    my $verdict = ! grep { $disabled_uc{$_} } @features;

    if ($apiv) {
        foreach (@features) {
            next unless /^DEPRECATEDIN_(\d+)_(\d+)_(\d+)$/;
            my $symdep = sprintf "%x%02x%02x", $1, $2, $3;
            $verdict = 0 if $apiv ge $symdep;
        }
    }

    return $verdict;
}

sub sorter_unix {
    my $by_name = OpenSSL::Ordinals::by_name();
    my %weight = (
        'FUNCTION'      => 1,
        'VARIABLE'      => 2
       );

    return sub {
        my $item1 = shift;
        my $item2 = shift;

        my $verdict = $weight{$item1->type()} <=> $weight{$item2->type()};
        if ($verdict == 0) {
            $verdict = $by_name->($item1, $item2);
        }
        return $verdict;
    };
}

sub sorter_linux {
    my $by_version = OpenSSL::Ordinals::by_version();
    my $by_unix = sorter_unix();

    return sub {
        my $item1 = shift;
        my $item2 = shift;

        my $verdict = $by_version->($item1, $item2);
        if ($verdict == 0) {
            $verdict = $by_unix->($item1, $item2);
        }
        return $verdict;
    };
}

sub writer_linux {
    my $thisversion = '';
    my $prevversion = '';

    for (@_) {
        if ($thisversion && $_->version() ne $thisversion) {
            print <<"_____";
}$prevversion;
_____
            $prevversion = " OPENSSL${SO_VARIANT}_$thisversion";
            $thisversion = '';  # Trigger start of next section
        }
        unless ($thisversion) {
            $thisversion = $_->version();
            print <<"_____";
OPENSSL${SO_VARIANT}_$thisversion {
    global:
_____
        }
        print '        ', $_->name(), ";\n";
    }

    print <<"_____";
    local: *;
}$prevversion;
_____
}

sub writer_aix {
    for (@_) {
        print $_->name(),"\n";
    }
}

sub writer_windows {
    print <<"_____";
;
; Definition file for the DLL version of the $libname library from OpenSSL
;

LIBRARY         $libname

EXPORTS
_____
    for (@_) {
        print "    ",$_->name(),"\n";
    }
}

sub writer_VMS {
    my @slot_collection = ();
    my $write_vector_slot_pair =
        sub {
            my $slot1 = shift;
            my $slot2 = shift;
            my $slotpair_text = " $slot1, -\n  $slot2, -\n"
        };

    my $last_num = 0;
    foreach (@_) {
        while (++$last_num < $_->number()) {
            push @slot_collection, [ 'SPARE', 'SPARE' ];
        }
        my $type = {
            FUNCTION    => 'PROCEDURE',
            VARIABLE    => 'DATA'
           } -> {$_->type()};
        my $s = $_->name();
        my $s_uc = uc($s);
        if ($s_uc eq $s) {
            push @slot_collection, [ "$s=$type", 'SPARE' ];
        } else {
            push @slot_collection, [ "$s_uc/$s=$type", "$s=$type" ];
        }
    }

    print <<"_____";
IDENTIFICATION=$config{version}
CASE_SENSITIVE=YES
SYMBOL_VECTOR=(-
_____
    # It's uncertain how long aggregated lines the linker can handle,
    # but it has been observed that at least 1024 characters is ok.
    # Either way, this means that we need to keep track of the total
    # line length of each "SYMBOL_VECTOR" statement.  Fortunately, we
    # can have more than one of those...
    my $symvtextcount = 16;     # The length of "SYMBOL_VECTOR=("
    while (@slot_collection) {
        my $pair = shift @slot_collection;
        my $pairtextlength =
            2                   # one space indentation and comma
            + length($pair->[0])
            + 1                 # postdent
            + 3                 # two space indentation and comma
            + length($pair->[1])
            + 1                 # postdent
            ;
        my $firstcomma = ',';

        if ($symvtextcount + $pairtextlength > 1024) {
            print <<"_____";
)
SYMBOL_VECTOR=(-
_____
            $symvtextcount = 16; # The length of "SYMBOL_VECTOR=("
        }
        if ($symvtextcount == 16) {
            $firstcomma = '';
        }
        print <<"_____";
 $firstcomma$pair->[0] -
  ,$pair->[1] -
_____
        $symvtextcount += $pairtextlength;
    }
    print <<"_____";
)
_____

    my ($libvmajor, $libvminor, $libvedit, $libvpatch) =
        $config{version} =~ /^(\d+)_(\d+)_(\d+)([a-z]{0,2})-.*$/;
    my $libvpatchnum = 0;
    for (split '', $libvpatch // '') {
        $libvpatchnum += ord(lc($_)) - 96;
        # To compensate because the letter 'z' is always followed by another,
        # i.e. doesn't add any value on its own
        $libvpatchnum-- if lc($_) eq 'z';
    }
    my $match1 = $libvmajor * 100 + $libvminor;
    my $match2 = $libvedit * 100 + $libvpatchnum;
    print <<"_____";
GSMATCH=LEQUAL,$match1,$match2
_____
}

sub writer_ctest {
    print <<'_____';
/*
 * Test file to check all DEF file symbols are present by trying
 * to link to all of them. This is *not* intended to be run!
 */

int main()
{
_____

    for (@_) {
        if ($_->type() eq 'VARIABLE') {
            print "\textern int ", $_->name(), '; /* type unknown */ /* ', $_->number(), ' ', $_->version(), " */\n";
        } else {
            print "\textern int ", $_->name(), '(); /* type unknown */ /* ', $_->number(), ' ', $_->version(), " */\n";
        }
    }
    print <<'_____';
}
_____
}
