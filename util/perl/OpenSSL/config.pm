#! /usr/bin/env perl
# Copyright 1998-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Determine the operating system and run ./Configure.  Far descendant from
# Apache's minarch and GuessOS.

package OpenSSL::config;

use strict;
use warnings;
use Getopt::Std;
use File::Basename;

# These control our behavior.
my $DRYRUN;
my $VERBOSE;
my $WAIT = 1;
my $WHERE = dirname($0);

# Machine type, etc., used to determine the platform
my $MACHINE;
my $RELEASE;
my $SYSTEM;
my $VERSION;
my $CCVER;
my $GCCVER;
my $GCC_BITS;
my $GCC_ARCH;

# Some environment variables; they will affect Configure
my $PERL = $ENV{PERL} // $^X // 'perl';
my $CONFIG_OPTIONS = $ENV{CONFIG_OPTIONS} // '';
my $CC = $ENV{CC} // 'cc';
my $CROSS_COMPILE = $ENV{CROSS_COMPILE} // "";
my $KERNEL_BITS = $ENV{KERNEL_BITS} // '';

# This is what we will set as the target for calling Configure.
my $options = '';

# Environment that will be passed to Configure
my $__CNF_CPPDEFINES = '';
my $__CNF_CPPINCLUDES = '';
my $__CNF_CPPFLAGS = '';
my $__CNF_CFLAGS = '';
my $__CNF_CXXFLAGS = '';
my $__CNF_LDFLAGS = '';
my $__CNF_LDLIBS = '';

# Pattern matches against "${SYSTEM}:${RELEASE}:${VERSION}:${MACHINE}"
my $simple_guess_patterns = [
    [ 'A\/UX:',               'm68k-apple-aux3' ],
    [ 'AIX:[3-9]:4:',         '${MACHINE}-ibm-aix' ],
    [ 'AIX:.*:[5-9]:',        '${MACHINE}-ibm-aix' ],
    [ 'AIX:',                 '${MACHINE}-ibm-aix3' ],
    [ 'HI-UX:',               '${MACHINE}-hi-hiux' ],
    [ 'IRIX:6.',              'mips3-sgi-irix' ],
    [ 'IRIX64:',              'mips4-sgi-irix64' ],
    [ 'Linux:[2-9]',          '${MACHINE}-whatever-linux2' ],
    [ 'Linux:1',              '${MACHINE}-whatever-linux1' ],
    [ 'GNU',                  'hurd-x86' ],
    [ 'LynxOS:',              '${MACHINE}-lynx-lynxos' ],
    # BSD/OS always says 386
    [ 'BSD\/OS:4.*',          'i486-whatever-bsdi4' ],
    [ 'BSD\/386:.*|BSD\/OS:', '${MACHINE}-whatever-bsdi' ],
    [ 'DragonFly:',           '${MACHINE}-whatever-dragonfly' ],
    [ 'FreeBSD:',             '${MACHINE}-whatever-freebsd' ],
    [ 'Haiku:',               '${MACHINE}-whatever-haiku' ],
    [ 'NetBSD:',              '${MACHINE}-whatever-netbsd' ],
    [ 'OpenBSD:',             '${MACHINE}-whatever-openbsd' ],
    [ 'OpenUNIX:',            '${MACHINE}-unknown-OpenUNIX${VERSION}' ],
    [ 'Paragon.*:',           'i860-intel-osf1' ],
    [ 'Rhapsody:',            'ppc-apple-rhapsody' ],
    [ 'SunOS:5.',             '${MACHINE}-whatever-solaris2' ],
    [ 'SunOS:',               '${MACHINE}-sun-sunos4' ],
    [ 'UNIX_System_V:4.*:',   '${MACHINE}-whatever-sysv4' ],
    [ 'VOS:.*:.*:i786',       'i386-stratus-vos' ],
    [ 'VOS:.*:.*:',           'hppa1.1-stratus-vos' ],
    [ '.*:4.*:R4.*:m88k',     '${MACHINE}-whatever-sysv4' ],
    [ 'DYNIX\/ptx:4.*:',      '${MACHINE}-whatever-sysv4' ],
    [ ':4.0:3.0:3[34]',       'i486-ncr-sysv4' ],
    [ 'ULTRIX:',              '${MACHINE}-unknown-ultrix' ],
    [ 'POSIX-BC',             'BS2000-siemens-sysv4' ],
    [ 'machten:',             '${MACHINE}-tenon-${SYSTEM}' ],
    [ 'library:',             '${MACHINE}-ncr-sysv4' ],
    [ 'ConvexOS:.*:11.0:',    '${MACHINE}-v11-${SYSTEM}' ],
    [ 'MINGW64.*:.*x86_64',   '${MACHINE}-whatever-mingw64' ],
    [ 'MINGW',                '${MACHINE}-whatever-mingw' ],
    [ 'CYGWIN',               '${MACHINE}-pc-cygwin' ],
    [ 'vxworks',              '${MACHINE}-whatever-vxworks' ],
    [ 'Darwin:.*Power',       'ppc-apple-darwin' ],
    [ 'Darwin:.*x86_64',      'x86_64-apple-darwin' ],
    [ 'Darwin:',              'i686-apple-darwin' ],
];

# More complex cases that require run-time code.
my $complex_sys_list = [
    [ 'HP-UX:', sub {
        my $HPUXVER = $RELEASE;
        $HPUXVER = s/[^.]*.[0B]*//;
        # HPUX 10 and 11 targets are unified
        return "${MACHINE}-hp-hpux1x" if $HPUXVER =~ m@1[0-9]@;
        return "${MACHINE}-hp-hpux";
    } ],

    [ 'BSD/386:.*:.*:.*486.*|BSD/OS:.*:.*:.*:.*486', sub {
        my $BSDVAR = `/sbin/sysctl -n hw.model`;
        return "i586-whatever-bsdi" if $BSDVAR =~ m@Pentium@;
        return "i386-whatever-bsdi";
    } ],

    [ 'FreeBSD:.*:.*:.*386', sub {
        my $VERS = $RELEASE;
        $VERS =~ s/[-(].*//;
        my $MACH = `sysctl -n hw.model`;
        $MACH = "i386" if $MACH =~ m@386@;
        $MACH = "i486" if $MACH =~ m@486@;
        $MACH = "i686" if $MACH =~ m@Pentium II@;
        $MACH = "i586" if $MACH =~ m@Pentium@;
        $MACH = "$MACHINE" if $MACH !~ /i.86/;
        my $ARCH = 'whatever';
        $ARCH = "pc" if $MACH =~ m@i[0-9]86@;
        return "${MACH}-${ARCH}-freebsd${VERS}";
    } ],

    [ 'NetBSD:.*:.*:.*386', sub {
        my $hw = `/usr/sbin/sysctl -n hw.model || /sbin/sysctl -n hw.model`;
        $hw =~  s@.*(.)86-class.*@i${1}86@;
        return "${hw}-whatever-netbsd";
    } ],

    [ 'OSF1:.*:.*:.*alpha', sub {
        my $OSFMAJOR = $RELEASE;
        $OSFMAJOR =~ 's/^V([0-9]*)\..*$/\1/';
        return "${MACHINE}-dec-tru64" if $OSFMAJOR =~ m@[45]@;
        return "${MACHINE}-dec-osf";
    } ],
];


# Run a command, return true if exit zero else false.
# Multiple args are glued together into a pipeline.
# Name comes from OpenSSL tests, often written as "ok(run(...."
sub okrun {
    my $command = join(' | ', @_);
    my $status = system($command) >> 8;
    return $status == 0;
}

# Give user a chance to abort/interrupt if interactive if interactive.
sub maybe_abort {
    if ( $WAIT && -t 1 ) {
        eval {
            local $SIG{ALRM} = sub { die "Timeout"; };
            local $| = 1;
            alarm(5);
            print "You have about five seconds to abort: ";
            my $ignored = <STDIN>;
            alarm(0);
        };
        print "\n" if $@ =~ /Timeout/;
    }
}

# Parse options.
sub call_getopt {
    our($opt_d);
    our($opt_h);
    our($opt_t);
    our($opt_v);
    our($opt_w);
    getopts("dhtvw");

    # Building on windows needs a VisualC target.
    my $iswin = $^O eq 'MSWin32';
    my $foundvc = 0;

    if ( $opt_h ) {
        print <<'EOF';
Usage: config [options] [args...]
  -d    Build with debugging when possible.
  -t    Test mode, do not run the Configure perl script.
  -v    Verbose mode, show the exact Configure call that is being made.
  -w    Do not wait after displaying any warnings.
  -h    This help.
All other arguments are passed to the Configure script.
See INSTALL for instructions.
EOF
        exit;
    }
    # All other parameters are passed to Configure
    foreach my $opt ( @ARGV ) {
        # Could make the VC- part optional, but that might cause
        # confusion.
        if ( $iswin && $opt =~ /^VC-(WIN32|WIN64A|WIN64I|CE)$/i ) {
            $opt = tr/a-z/A-Z/;
            $opt = "VC-$opt" unless $opt =~ /^VC-/;
            $foundvc = 1;
        }
        $options .= " $opt";
    }
    if ( $iswin && !$foundvc ) {
        print <<EOF;
WARNING: Did not find VisualC target.  See INSTALL for details.
EOF
        maybe_abort();
    }
    $options = " --debug" if $opt_d;
    $DRYRUN = $opt_t;
    $VERBOSE = $opt_v || $opt_t;
    $WAIT = 0 if $opt_w;
}

# call uname with specified arg, return result.
sub uname {
    my $arg = shift;
    open UNAME, "uname $arg 2>/dev/null|" or return "unknown";
    my $line = <UNAME>;
    close UNAME;
    $line =~ s/[\r\n]+$//;
    return "unknown" if $line eq '';
    return $line;
}

# Set machine type, release, etc., variables.
sub get_machine_etc {
    $MACHINE = $ENV{MACHINE} // uname('-m');
    $RELEASE = $ENV{RELEASE} // uname('-r');
    $SYSTEM = $ENV{SYSTEM} // uname("-s");
    $VERSION = uname('-v');
}

# Expand variable references in a string.
sub expand {
    my $var = shift;
    $var =~ s/\$\{MACHINE\}/${MACHINE}/;
    return $var;
}

# Add no-xxx if someone removed a crypto algorithm directory.
# TODO: This should be moved to Configure.
my @cryptodir = (
    'aes', 'aria', 'bf', 'camellia', 'cast', 'des', 'dh', 'dsa', 'ec', 'hmac',
    'idea', 'md2', 'md5', 'mdc2', 'rc2', 'rc4', 'rc5', 'ripemd', 'rsa',
    'seed', 'sha', 'sm2', 'sm3', 'sm4'
);
sub remove_removed_crypto_directories {
    foreach my $d ( @cryptodir ) {
        $options .= " no-$d" if ! -d "$WHERE/crypto/$d";
    }
}

# Look for ISC/SCO with its unique uname program
sub is_sco_uname {
    open UNAME, "uname -X 2>/dev/null|" or return '';
    my $line = "";
    while ( <UNAME> ) {
        chop;
        $line = $_ if m@^Release@;
    }
    close UNAME;
    return "" if $line eq '';
    my @fields = split($line);
    return $fields[2];
}

sub get_sco_type {
    my $REL = shift;

    if ( -f "/etc/kconfig" ) {
        return "${MACHINE}-whatever-isc4" if $REL eq '4.0' || $REL eq '4.1';
    } else {
        return "whatever-whatever-sco3" if $REL eq '3.2v4.2';
        return "whatever-whatever-sco5" if $REL =~ m@3\.2v5\.0.*@;
        if ( $REL eq "4.2MP" ) {
            return "whatever-whatever-unixware20" if $VERSION =~ m@2\.0.*@;
            return "whatever-whatever-unixware21" if $VERSION =~ m@2\.1.*@;
            return "whatever-whatever-unixware2" if $VERSION =~ m@2.*@;
        }
        return "whatever-whatever-unixware1" if $REL eq "4.2";
        if ( $REL =~ m@5.*@ ) {
            # We hardcode i586 in place of ${MACHINE} for the following
            # reason: even though Pentium is minimum requirement for
            # platforms in question, ${MACHINE} gets always assigned to
            # i386. This means i386 gets passed to Configure, which will
            # cause bad assembler code to be generated.
            return "i586-sco-unixware7" if $VERSION =~ m@[678].*@;
        }
    }
}

# Return the cputype-vendor-osversion
sub guess_system {
    # Special-cases for ISC, SCO, Unixware
    my $REL = is_sco_uname();
    if ( $REL ne "" ) {
        my $result = get_sco_type($REL);
        return expand($result) if $result ne '';
    }

    # Now pattern-match
    my $sys = "${SYSTEM}:${RELEASE}:${VERSION}:${MACHINE}";

    # Simple cases
    foreach my $tuple ( @$simple_guess_patterns ) {
        my $pat = @$tuple[0];
        # Trailing $ omitted on purpose.
        next if $sys !~ /^$pat/;
        my $result = @$tuple[1];
        return expand($result);
    }

    # Complex cases.
    foreach my $tuple ( @$complex_sys_list ) {
        my $pat = @$tuple[0];
        # Trailing $ omitted on purpose.
        next if $sys !~ /^$pat/;
        my $ref = @$tuple[1];
        my $result = &$ref;
        return expand($result);
    }

    # Oh well.
    return "${MACHINE}-whatever-${SYSTEM}";
}

# Figure out CC, GCCVAR, etc.
sub determine_compiler_settings {
    if ( "$CROSS_COMPILE$CC" eq '' ) {
        $GCCVER = `gcc -dumpversion 2>/dev/null`;
        if ( $GCCVER ne "" ) {
            # Strip off whatever prefix egcs prepends the number with.
            # Hopefully, this will work for any future prefixes as well.
            $GCCVER =~ s/^[a-zA-Z]*\-//;
	    # Since gcc 3.1 gcc --version behaviour has changed, but
            # -dumpversion gives us what we want though, so use that.
            # We only want the major and minor version numbers.  The
            # pattern is deliberate; single digit before and after first
            # dot, e.g. 2.95.1 gives 29
            $GCCVER =~ s/([0-9])\.([0-9]).*/$1$2/;
            $GCCVER = int($GCCVER);
            $CC = 'gcc';
        }
    }

    $GCCVER //= 0;

    if ( $SYSTEM eq "HP-UX" ) {
        # By default gcc is a ILP32 compiler (with long long == 64).
        $GCC_BITS = "32";
        if ( $GCCVER >= 30 ) {
            # PA64 support only came in with gcc 3.0.x.
            # We check if the preprocessor symbol __LP64__ is defined.
            if ( okrun('echo __LP64__',
                    'gcc -v -E -x c - 2>/dev/null',
                    'grep "^__LP64__" 2>&1 >/dev/null') ) {
                # __LP64__ has slipped through, it therefore is not defined
            } else {
                $GCC_BITS = '64';
            }
        }
        return;
    }

    if ( ${SYSTEM} eq 'AIX' ) {
        # favor vendor cc over gcc
        if ( okrun('(cc) 2>&1',
                'grep -iv "not found" >/dev/null') ) {
            $CC = 'cc';
        }
        return;
    }

    if ( $SYSTEM eq "SunOS" ) {
        if ( $GCCVER >= 30 ) {
            # 64-bit ABI isn't officially supported in gcc 3.0, but seems
            # to be working; at the very least 'make test' passes.
            if ( okrun('gcc -v -E -x c /dev/null 2>&1',
                    'grep __arch64__ >/dev/null') ) {
                $GCC_ARCH = "-m64"
            } else {
                $GCC_ARCH = "-m32"
            }
        }
        # check for WorkShop C, expected output is "cc: blah-blah C x.x"
        $CCVER = `(cc -V 2>&1) 2>/dev/null | egrep -e '^cc: .* C [0-9]\.[0-9]'`;
        $CCVER =~ s/.* C \([0-9]\)\.\([0-9]\).*/$1$2/;
        $CCVER //= 0;
        if ( $MACHINE ne 'i86pc' && $CCVER > 40 ) {
            # overrides gcc!!!
            $CC = 'cc';
            if ( $CCVER == 50 ) {
                print <<'EOF';
WARNING! Found WorkShop C 5.0.
         Make sure you have patch #107357-01 or later applied.
EOF
                maybe_abort();
            }
        }
    }
}

# Map GUESSOS into OpenSSL terminology. Also sets some of variables
# like $options, $__CNX_xxx.  And uses some, like the KERNEL flags
# and MACHINE.
# It would be nice to fix this so that this weren't necessary. :( XXX
sub map_guess {
    my $GUESSOS = shift;
    my $OUT;
    return 'uClinux-dist64' if $GUESSOS =~ 'uClinux.*64.*';
    return 'uClinux-dist' if $GUESSOS =~ 'uClinux.*';
    return "irix-mips3-$CC" if $GUESSOS =~ 'mips3-sgi-irix';
    if ( $GUESSOS =~ 'mips4-sgi-irix64' ) {
        print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure irix64-mips4-$CC
EOF
        maybe_abort();
        return "irix-mips3-$CC";
    }
    return "rhapsody-ppc-cc" if $GUESSOS =~ 'ppc-apple-rhapsody';
    if ( $GUESSOS =~ 'ppc-apple-darwin' ) {
        my $ISA64 = `sysctl -n hw.optional.64bitops 2>/dev/null`;
        if ( $ISA64 == 1 && $KERNEL_BITS eq '' ) {
            print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure darwin64-ppc-cc
EOF
            maybe_abort();
        }
        return "darwin64-ppc-cc" if $ISA64 == 1 && $KERNEL_BITS eq '64';
        return "darwin-ppc-cc";
    }
    if ( $GUESSOS =~ 'i.86-apple-darwin' ) {
        my $ISA64 = `sysctl -n hw.optional.x86_64 2>/dev/null`;
        if ( $ISA64 == 1 && $KERNEL_BITS eq '' ) {
            print <<EOF;
WARNING! To build 64-bit package, do this:
         KERNEL_BITS=64 $WHERE/config $options
EOF
            maybe_abort();
        }
        return "darwin64-x86_64-cc" if $ISA64 == 1 && $KERNEL_BITS eq '64';
        return "darwin-i386-cc";
    }
    if ( $GUESSOS =~ 'x86_64-apple-darwin' ) {
        return "darwin-i386-cc" if $KERNEL_BITS eq '32';

        print <<EOF;
WARNING! To build 32-bit package, do this:
         KERNEL_BITS=32 $WHERE/config $options
EOF
        maybe_abort();
        return "darwin64-x86_64-cc"
    }
    if ( $GUESSOS =~ 'armv6+7-.*-iphoneos' ) {
        $__CNF_CFLAGS .= " -arch armv6 -arch armv7";
        $__CNF_CXXFLAGS .= " -arch armv6 -arch armv7";
        return "iphoneos-cross";
    }
    if ( $GUESSOS =~ '.*-.*-iphoneos' ) {
        $__CNF_CFLAGS .= " -arch ${MACHINE}";
        $__CNF_CXXFLAGS .= " -arch ${MACHINE}";
        return "iphoneos-cross";
    }
    return "ios64-cross" if $GUESSOS =~ 'arm64-.*-iphoneos|.*-.*-ios64';
    if ( $GUESSOS =~ 'alpha-.*-linux2' ) {
        my $ISA = `awk '/cpu model/{print \$4;exit(0);}' /proc/cpuinfo`;
        $ISA //= 'generic';
        if ( $CC eq "gcc" ) {
            if ( $ISA =~ 'EV5|EV45' ) {
                $__CNF_CFLAGS .= " -mcpu=ev5";
                $__CNF_CFLAGS .= " -mcpu=ev5";
            } elsif ( $ISA =~ 'EV56|PCA56' ) {
                $__CNF_CFLAGS .= " -mcpu=ev56";
                $__CNF_CXXFLAGS .= " -mcpu=ev56";
            } else {
                $__CNF_CFLAGS .= "-mcpu=ev6";
                $__CNF_CXXFLAGS .= "-mcpu=ev6";
            }
        }
        return "linux-alpha-$CC";
    }
    if ( $GUESSOS =~ 'ppc64-.*-linux2' ) {
        if ( $KERNEL_BITS eq '' ) {
            print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure linux-ppc64
EOF
            maybe_abort();
        }
        return "linux-ppc64" if $KERNEL_BITS eq '64';
        if (!okrun('echo __LP64__',
                'gcc -E -x c - 2>/dev/null',
                'grep "^__LP64__" 2>&1 >/dev/null') ) {
            $__CNF_CFLAGS .= " -m32";
            $__CNF_CXXFLAGS .= " -m32";
        }
        return "linux-ppc";
    }
    return "linux-ppc64le" if $GUESSOS =~ 'ppc64le-.*-linux2';
    return "linux-ppc" if $GUESSOS =~ 'ppc-.*-linux2';
    if ( $GUESSOS =~ 'mips64.*-*-linux2' ) {
        print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure linux64-mips64
EOF
        maybe_abort();
        return "linux-mips64";
    }
    return "linux-mips32" if $GUESSOS =~ 'mips.*-.*-linux2';
    return "vxworks-ppc60x" if $GUESSOS =~ 'ppc60x-.*-vxworks*';
    return "vxworks-ppcgen" if $GUESSOS =~ 'ppcgen-.*-vxworks*';
    return "vxworks-pentium" if $GUESSOS =~ 'pentium-.*-vxworks*';
    return "vxworks-simlinux" if $GUESSOS =~ 'simlinux-.*-vxworks*';
    return "vxworks-mips" if $GUESSOS =~ 'mips-.*-vxworks*';
    return "linux-generic64 -DL_ENDIAN" if $GUESSOS =~ 'e2k-.*-linux*';
    return "linux-ia64" if $GUESSOS =~ 'ia64-.*-linux.';
    if ( $GUESSOS =~ 'sparc64-.*-linux2' ) {
        print <<EOF;
WARNING! If you *know* that your GNU C supports 64-bit/V9 ABI and you
         want to build 64-bit library, do this:
         $WHERE/Configure linux64-sparcv9
EOF
        maybe_abort();
        return "linux-sparcv9";
    }
    if ( $GUESSOS =~ 'sparc-.*-linux2' ) {
        my $KARCH = `awk '/^type/{print \$3;exit(0);}' /proc/cpuinfo`;
        $KARCH //= "sun4";
        return "linux-sparcv9" if $KARCH =~ 'sun4u*';
        return "linux-sparcv8" if $KARCH =~ 'sun4[md]';
        $__CNF_CPPFLAGS .= " -DB_ENDIAN";
        return "linux-generic32";
    }
    if ( $GUESSOS =~ 'parisc.*-.*-linux2' ) {
        # 64-bit builds under parisc64 linux are not supported and
        # compiler is expected to generate 32-bit objects...
        my $CPUARCH =
        `awk '/cpu family/{print substr(\$5,1,3); exit(0);}' /proc/cpuinfo`;
        my $CPUSCHEDULE =
        `awk '/^cpu.[ 	]*: PA/{print substr(\$3,3); exit(0);}' /proc/cpuinfo`;
        # TODO XXX  Model transformations
        # 0. CPU Architecture for the 1.1 processor has letter suffixes. We
        #    strip that off assuming no further arch. identification will ever
        #    be used by GCC.
        # 1. I'm most concerned about whether is a 7300LC is closer to a 7100
        #    versus a 7100LC.
        # 2. The variant 64-bit processors cause concern should GCC support
        #    explicit schedulers for these chips in the future.
        #         PA7300LC -> 7100LC (1.1)
        #         PA8200   -> 8000   (2.0)
        #         PA8500   -> 8000   (2.0)
        #         PA8600   -> 8000   (2.0)
        $CPUSCHEDULE =~ s/7300LC/7100LC/;
        $CPUSCHEDULE =~ s/8.00/8000/;
        # Finish Model transformations
        $__CNF_CPPFLAGS .= " -DB_ENDIAN";
        $__CNF_CFLAGS .= " -mschedule=$CPUSCHEDULE -march=$CPUARCH";
        $__CNF_CXXFLAGS .= " -mschedule=$CPUSCHEDULE -march=$CPUARCH";
        return "linux-generic32";
    }
    return "linux-generic32" if $GUESSOS =~ 'armv[1-3].*-.*-linux2';
    if ( $GUESSOS =~ 'armv[7-9].*-.*-linux2' ) {
        $__CNF_CFLAGS .= " -march=armv7-a";
        $__CNF_CXXFLAGS .= " -march=armv7-a";
        return "linux-armv4";
    }
    return "linux-armv4" if $GUESSOS =~ 'arm.*-.*-linux2';
    return "linux-aarch64" if $GUESSOS =~ 'aarch64-.*-linux2';
    if ( $GUESSOS =~ 'sh.*b-.*-linux2' ) {
        $__CNF_CPPFLAGS .= " -DB_ENDIAN";
        return "linux-generic32";
    }
    if ( $GUESSOS =~ 'sh.*-.*-linux2' ) {
        $__CNF_CPPFLAGS .= " -DL_ENDIAN";
        return "linux-generic32";
    }
    if ( $GUESSOS =~ 'm68k.*-.*-linux2' || $GUESSOS =~ 's390-.*-linux2' ) {
        $__CNF_CPPFLAGS .= " -DB_ENDIAN";
        return "linux-generic32";
    }
    if ( $GUESSOS =~ 's390x-.*-linux2' ) {
        # Disabled until a glibc bug is fixed; see Configure.
        if (0 || okrun(
                'egrep -e \'^features.* highgprs\' /proc/cpuinfo >/dev/null') )
        {
            print <<EOF;
WARNING! To build "highgprs" 32-bit package, do this:
         $WHERE/Configure linux32-s390x
EOF
            maybe_abort();
        }
        return "linux64-s390x";
    }
    if ( $GUESSOS =~ 'x86_64-.*-linux.' ) {
        return "linux-x32"
            if okrun("$CC -dM -E -x c /dev/null 2>&1",
                'grep -q ILP32 >/dev/null');
        return "linux-x86_64";
    }
    if ( $GUESSOS =~ '.*86-.*-linux2' ) {
        # On machines where the compiler understands -m32, prefer a
        # config target that uses it
        return "linux-x86"
            if okrun("$CC -m32 -E -x c /dev/null >/dev/null 2>&1");
        return "linux-elf"
    }
    return "linux-aout" if $GUESSOS =~ '.*86-.*-linux1';
    return "linux-generic32" if $GUESSOS =~ '.*-.*-linux.';
    if ( $GUESSOS =~ 'sun4[uv].*-.*-solaris2' ) {
        my $ISA64 = `isainfo 2>/dev/null | grep sparcv9`;
        if ( $ISA64 ne "" && $KERNEL_BITS eq '' ) {
            if ( $CC eq "cc" && $CCVER >= 50 ) {
                print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure solaris64-sparcv9-cc
EOF
                maybe_abort();
            } elsif ( $CC eq "gcc" && $GCC_ARCH eq "-m64" ) {
                # $GCC_ARCH denotes default ABI chosen by compiler driver
                # (first one found on the $PATH). I assume that user
                # expects certain consistency with the rest of his builds
                # and therefore switch over to 64-bit. <appro>
                print <<EOF;
WARNING! To build 32-bit package, do this:
         $WHERE/Configure solaris-sparcv9-gcc
EOF
                maybe_abort();
                return "solaris64-sparcv9-gcc";
            } elsif ( $GCC_ARCH eq "-m32" ) {
                print <<EOF;
NOTICE! If you *know* that your GNU C supports 64-bit/V9 ABI and you wish
        to build 64-bit library, do this:
        $WHERE/Configure solaris64-sparcv9-gcc
EOF
                maybe_abort();
            }
        }
        return "solaris64-sparcv9-$CC" if $ISA64 ne "" && $KERNEL_BITS eq '64';
        return "solaris-sparcv9-$CC";
    }
    return "solaris-sparcv8-$CC" if $GUESSOS =~ 'sun4m-.*-solaris2';
    return "solaris-sparcv8-$CC" if $GUESSOS =~ 'sun4d-.*-solaris2';
    return "solaris-sparcv7-$CC" if $GUESSOS =~ 'sun4.*-.*-solaris2';
    if ( $GUESSOS =~ '.*86.*-.*-solaris2' ) {
        my $ISA64 = `isainfo 2>/dev/null | grep amd64`;
        my $KB = $KERNEL_BITS // '64';
        return "solaris64-x86_64-$CC" if $ISA64 ne "" && $KB eq '64';
        my $REL = uname('-r');
        $REL =~ s/5\.//;
        $options .= " no-sse2" if int($REL) < 10;
        return "solaris-x86-$CC";
    }
    return "sunos-$CC" if $GUESSOS =~ '.*-.*-sunos4';
    if ( $GUESSOS =~ '.*86.*-.*-bsdi4' ) {
        $options .= " no-sse2";
        $__CNF_LDFLAGS .= " -ldl";
        return "BSD-x86-elf";
    }
    if ( $GUESSOS =~ 'alpha.*-.*-.*bsd.*' ) {
        $__CNF_CPPFLAGS .= " -DL_ENDIAN";
        return "BSD-generic64";
    }
    if ( $GUESSOS =~ 'powerpc64-.*-.*bsd.*' ) {
        $__CNF_CPPFLAGS .= " -DB_ENDIAN";
        return "BSD-generic64";
    }
    return "BSD-sparc64" if $GUESSOS =~ 'sparc64-.*-.*bsd.*';
    return "BSD-ia64" if $GUESSOS =~ 'ia64-.*-.*bsd.*';
    return "BSD-x86_64" if $GUESSOS =~ 'x86_64-.*-dragonfly.*';
    return "BSD-x86_64" if $GUESSOS =~ 'amd64-.*-.*bsd.*';
    if ( $GUESSOS =~ '.*86.*-.*-.*bsd.*' ) {
        # mimic ld behaviour when it's looking for libc...
        my $libc;
        if ( -l "/usr/lib/libc.so" ) {
            $libc = "/usr/lib/libc.so";
        } else {
            # ld searches for highest libc.so.* and so do we
            $libc = 
            `(ls /usr/lib/libc.so.* /lib/libc.so.* | tail -1) 2>/dev/null`;
        }
        my $what = `file -L $libc 2>/dev/null`;
        return "BSD-x86-elf" if $what =~ /ELF/;
        $options .= " no-sse2";
        return "BSD-x86";
    }
    return "BSD-generic32" if $GUESSOS =~ '.*-.*-.*bsd.*';
    return "haiku-x86_64" if $GUESSOS =~ 'x86_64-.*-haiku';
    return "haiku-x86" if $GUESSOS =~ '.*-.*-haiku';
    return "osf1-alpha-cc" if $GUESSOS =~ '.*-.*-osf';
    return "tru64-alpha-cc" if $GUESSOS =~ '.*-.*-tru64';
    if ( $GUESSOS =~ '.*-.*-[Uu]nix[Ww]are7' ) {
        $options .= "no-sse2";
        return "unixware-7-gcc" if $CC eq "gcc";
        $__CNF_CPPFLAGS .= " -D__i386__";
        return "unixware-7";
    }
    if ( $GUESSOS =~ '.*-.*-[Uu]nix[Ww]are20*' ) {
        $options .= " no-sse2 no-sha512";
        return "unixware-2.0";
    }
    if ( $GUESSOS =~ '.*-.*-[Uu]nix[Ww]are21*' ) {
        $options .= " no-sse2 no-sha512";
        return "unixware-2.1";
    }
    if ( $GUESSOS =~ '.*-.*-vos' ) {
        $options .= " no-threads no-shared no-asm no-dso";
        return "vos-$CC";
    }
    return "BS2000-OSD" if $GUESSOS =~ 'BS2000-siemens-sysv4';
    return "Cygwin-x86" if $GUESSOS =~ 'i[3456]86-.*-cygwin';
    return "Cygwin-${MACHINE}" if $GUESSOS =~ '.*-.*-cygwin';
    return "android-x86" if $GUESSOS =~ 'x86-.*-android|i.86-.*-android';
    if ( $GUESSOS =~ 'armv[7-9].*-.*-android' ) {
        $__CNF_CFLAGS .= " -march=armv7-a";
        $__CNF_CXXFLAGS .= " -march=armv7-a";
        return "android-armeabi";
    }
    return "android-armeabi" if $GUESSOS =~ 'arm.*-.*-android';
    if ( $GUESSOS =~ '.*-hpux1.*' ) {
        $OUT = "hpux64-parisc2-gcc" if $CC = "gcc" && $GCC_BITS eq '64';
        $KERNEL_BITS //= `getconf KERNEL_BITS 2>/dev/null` // '32';
        # See <sys/unistd.h> for further info on CPU_VERSION.
        my $CPU_VERSION = `getconf CPU_VERSION 2>/dev/null` // 0;
        $__CNF_CPPFLAGS .= " -D_REENTRANT";
        if ( $CPU_VERSION >= 768 ) {
            # IA-64 CPU
            return "hpux64-ia64-cc" if $KERNEL_BITS eq '64' && $CC eq "cc";
            return "hpux-ia64-cc"
        }
        if ( $CPU_VERSION >= 532 ) {
            # PA-RISC 2.x CPU
            # PA-RISC 2.0 is no longer supported as separate 32-bit
            # target. This is compensated for by run-time detection
            # in most critical assembly modules and taking advantage
            # of 2.0 architecture in PA-RISC 1.1 build.
            $OUT //= "hpux-parisc1_1-${CC}";
            if ( $KERNEL_BITS eq '64' && $CC eq "cc" ) {
                print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure hpux64-parisc2-cc
EOF
                maybe_abort();
            }
            return $OUT;
        }
        # PA-RISC 1.1+ CPU?
        return "hpux-parisc1_1-${CC}" if $CPU_VERSION >= 528;
        # PA-RISC 1.0 CPU
        return "hpux-parisc-${CC}" if $CPU_VERSION >= 523;
        # Motorola(?) CPU
        return "hpux-$CC";
        return $OUT;
    }
    return "hpux-parisc-$CC" if $GUESSOS =~ '.*-hpux';
    if ( $GUESSOS =~ '.*-aix' ) {
        $KERNEL_BITS //= `getconf KERNEL_BITMODE 2>/dev/null`;
        $KERNEL_BITS //= '32';
        my $OBJECT_MODE //= 32;
        if ( $CC eq "gcc" ) {
            $OUT = "aix-gcc";
            if ( $OBJECT_MODE == 64 ) {
                print 'Your $OBJECT_MODE was found to be set to 64';
                $OUT = "aix64-gcc"
            }
        } elsif ( $OBJECT_MODE == 64 ) {
            print 'Your $OBJECT_MODE was found to be set to 64';
            $OUT = "aix64-cc";
        } else {
            $OUT = "aix-cc";
            if ( $KERNEL_BITS eq '64' ) {
                print <<EOF;
WARNING! To build 64-bit package, do this:
         $WHERE/Configure aix64-cc
EOF
                maybe_abort();
            }
        }
        if ( okrun(
                "lsattr -E -O -l `lsdev -c processor|awk '{print \$1;exit}'`",
                'grep -i powerpc) >/dev/null 2>&1') ) {
            # this applies even to Power3 and later, as they return
            # PowerPC_POWER[345]
        } else {
            $options .= " no-asm";
        }
        return $OUT;
    }

    # Last case, return "z" from x-y-z
    my @fields = split(/-/, $GUESSOS);
    return $fields[2];
}

# gcc < 2.8 does not support -march=ultrasparc
sub check_solaris_sparc8 {
    my $OUT = shift;
    if ( $OUT eq 'solaris-sparcv9-gcc' && $GCCVER < 28 ) {
        print <<EOF;
WARNING! Downgrading to solaris-sparcv8-gcc
         Upgrade to gcc-2.8 or later.
EOF
      maybe_abort();
      return 'solaris-sparcv8-gcc';
    }
    if ( $OUT eq "linux-sparcv9" && $GCCVER < 28 ) {
      print <<EOF;
WARNING! Downgrading to linux-sparcv8
         Upgrade to gcc-2.8 or later.
EOF
      maybe_abort();
      return 'linux-sparcv8';
    }
    return $OUT;
}

# Append $CC to the target if that's in the Config list.
sub check_target_exists {
    my $OUT = shift;
    my %table;

    open T, "$PERL $WHERE/Configure LIST|" or die "Can't get LIST, $!";
    while ( <T> ) {
        chop;
        $table{$_} = 1;
    }
    close T;
    return "$OUT-$CC" if defined $table{"$OUT-$CC"};
    return "$OUT" if defined $table{$OUT};
    print "This system ($OUT) is not supported. See INSTALL for details.\n";
    exit 1;
}


###
###   MAIN PROCESSING
###

# Common part, does all the real work.
sub common {
    my $showguess = shift;

    get_machine_etc();
    my $GUESSOS = guess_system();
    print "Operating system: $GUESSOS\n" if $VERBOSE || $showguess;
    $options .= " 386" if $GUESSOS =~ /i386-/;
    remove_removed_crypto_directories();
    determine_compiler_settings();
    my $TARGET = map_guess($GUESSOS) // $CC;
    $TARGET = check_solaris_sparc8($TARGET);
    $TARGET = check_target_exists($TARGET);
    $options .= " $CONFIG_OPTIONS" if $CONFIG_OPTIONS ne '';
    return $TARGET;
}

##  If called from Configure
sub get_platform {
    my $ref = shift;
    my %options = %{$ref};
    $VERBOSE = 1 if defined $options{verbose};
    $options .= " --debug" if defined $options{debug};
    $WAIT = 0 if defined $options{nowait};

    my $TARGET = common(0);

    # Populate the environment settings.
    my %env;
    $env{__CNF_CPPDEFINES} = $__CNF_CPPDEFINES;
    $env{__CNF_CPPINCLUDES} = $__CNF_CPPINCLUDES;
    $env{__CNF_CPPFLAGS} = $__CNF_CPPFLAGS;
    $env{__CNF_CFLAGS} = $__CNF_CFLAGS;
    $env{__CNF_CXXFLAGS} = $__CNF_CXXFLAGS;

    # Prepare results and return them
    my %ret = {
        'target' => $TARGET,
        'options' => $options,
        'envvars' => %env,
    };
    return %ret;
}


# If running tandlone (via the "config" shell script)
sub main {
    call_getopt();

    my $TARGET = common(1);

    if ( $VERBOSE ) {
        print <<EOF;

export __CNF_CPPDEFINES="$__CNF_CPPDEFINES"
export __CNF_CPPINCLUDES="$__CNF_CPPINCLUDES"
export __CNF_CPPFLAGS="$__CNF_CPPFLAGS"
export __CNF_CFLAGS="$__CNF_CFLAGS"
export __CNF_CXXFLAGS="$__CNF_CXXFLAGS"
export __CNF_LDFLAGS="$__CNF_LDFLAGS"
export __CNF_LDLIBS="$__CNF_LDLIBS"
$PERL $WHERE/Configure $TARGET $options
EOF
    }

    return if $DRYRUN;

    print "\n";
    $ENV{__CNF_CPPDEFINES} = $__CNF_CPPDEFINES;
    $ENV{__CNF_CPPINCLUDES} = $__CNF_CPPINCLUDES;
    $ENV{__CNF_CPPFLAGS} = $__CNF_CPPFLAGS;
    $ENV{__CNF_CFLAGS} = $__CNF_CFLAGS;
    $ENV{__CNF_CXXFLAGS} = $__CNF_CXXFLAGS;
    $ENV{__CNF_LDFLAGS} = $__CNF_LDFLAGS;
    $ENV{__CNF_LDLIBS} = $__CNF_LDLIBS;
    exit 1 if ! okrun("$PERL $WHERE/Configure $TARGET $options");
}

1;
