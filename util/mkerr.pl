#! /usr/bin/env perl
# Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
my $errors       = 0;
my $config       = "crypto/err/openssl.ec";
my $debug        = 0;
my $unref        = 0;
my $rebuild      = 0;
my $internal     = 0;
my $reindex      = 0;
my $dowrite      = 1;
my @t            = localtime();
my $YEAR         = $t[5] + 1900;

sub help
{
    print STDERR <<"EOF";
mkerr.pl [options] [files...]

Options:

    -conf FILE  Use the named config file FILE instead of the default.

    -debug      Verbose output debugging on stderr.

    -rebuild    Rebuild all header and C source files, even if there
                were no changes.

    -reindex    Ignore previously assigned values (except for R records in
                the config file) and renumber everything starting at 100.

    -nowrite    Do not write the header/source files, even if changed.

    -internal   Generate code that is to be built as part of OpenSSL itself.
                Also scans internal list of files.

    -unref      List all unreferenced function and reason codes on stderr;
                implies -nowrite.

    -help       Show this help text.

    ...         Additional arguments are added to the file list to scan,
                if '-internal' was NOT specified on the command line.

EOF
}

while ( @ARGV ) {
    my $arg = $ARGV[0];
    last unless $arg =~ /-.*/;
    $arg = $1 if $arg =~ /-(-.*)/;
    if ( $arg eq "-conf" ) {
        $config = $ARGV[1];
        shift @ARGV;
    } elsif ( $arg eq "-debug" ) {
        $debug = 1;
        $unref = 1;
    } elsif ( $arg eq "-rebuild" ) {
        $rebuild = 1;
    } elsif ( $arg eq "-reindex" ) {
        $reindex = 1;
    } elsif ( $arg eq "-internal" ) {
        $internal = 1;
    } elsif ( $arg eq "-unref" ) {
        $unref = 1;
        $dowrite = 0;
    } elsif ( $arg eq "-nowrite" ) {
        $dowrite = 0;
    } elsif ( $arg =~ /-*h(elp)?/ ) {
        &help();
        exit;
    } elsif ( $arg =~ /-.*/ ) {
        die "Unknown option $arg; use -h for help.\n";
    }
    shift @ARGV;
}

my @source;
if ( $internal ) {
    die "Extra parameters given.\n" if @ARGV;
    @source = ( glob('crypto/*.c'), glob('crypto/*/*.c'),
                glob('ssl/*.c'), glob('ssl/*/*.c') );
} else {
    @source = @ARGV;
}

# Data parsed out of the config and state files.
my %hinc;       # lib -> header
my %libinc;     # header -> lib
my %cskip;      # error_file -> lib
my %errorfile;  # lib -> error file name
my %fmax;       # lib -> max assigned function code
my %rmax;       # lib -> max assigned reason code
my %fassigned;  # lib -> colon-separated list of assigned function codes
my %rassigned;  # lib -> colon-separated list of assigned reason codes
my %fnew;       # lib -> count of new function codes
my %rnew;       # lib -> count of new reason codes
my %rextra;     # "extra" reason code -> lib
my %rcodes;     # reason-name -> value
my %ftrans;     # old name -> #define-friendly name (all caps)
my %fcodes;     # function-name -> value
my $statefile;  # state file with assigned reason and function codes

# Read and parse the config file
open(IN, "$config") || die "Can't open config file $config, $!,";
while ( <IN> ) {
    next if /^#/ || /^$/;
    if ( /^L\s+(\S+)\s+(\S+)\s+(\S+)/ ) {
        $hinc{$1}   = $2;
        $libinc{$2} = $1;
        $cskip{$3}  = $1;
        if ( $3 ne "NONE" ) {
            $errorfile{$1} = $3;
            $fmax{$1}      = 100;
            $rmax{$1}      = 100;
            $fassigned{$1} = ":";
            $rassigned{$1} = ":";
            $fnew{$1}      = 0;
            $rnew{$1}      = 0;
        }
    } elsif ( /^R\s+(\S+)\s+(\S+)/ ) {
        $rextra{$1} = $2;
        $rcodes{$1} = $2;
    } elsif ( /^S\s+(\S+)/ ) {
        $statefile = $1;
    } else {
        die "Illegal config line $_\n";
    }
}
close IN;

if ( ! $statefile ) {
    $statefile = $config;
    $statefile =~ s/.ec/.txt/;
}

# The statefile has all the previous assignments.
if ( ! $reindex && $statefile ) {
    open(STATE, "<$statefile") || die "Can't open $statefile, $!";

    # Scan function and reason codes and store them: keep a note of the
    # maximum code used.
    while ( <STATE> ) {
        next if /^#/ || /^$/;
        die "Bad line in $statefile, $_\n" unless /(\S+)\s+(\S+)/;
        my $name = $1;
        my $code = $2;
        my $lib = $name;
        $lib =~ s/_.*//;
        if ( $1 eq "R" ) {
            $rcodes{$name} = $code;
            die "$lib reason code $code colliision at $name\n"
                if $rassigned{$lib} =~ /:$code:/;
            $rassigned{$lib} .= "$code:";
            if ( !exists $rextra{$name} ) {
                $rmax{$lib} = $code if $code > $rmax{$lib};
            }
        } else {
            die "$lib function code $code collision at $name\n"
                if $fassigned{$lib} =~ /:$code:/;
            $fassigned{$lib} .= "$code:";
            $fmax{$lib} = $code if $code > $fmax{$lib};
            $fcodes{$name} = $code;
        }
    }
    close(STATE);

    if ( $debug ) {
        foreach my $lib ( keys %rmax ) {
            print STDERR "Max reason code rmax{${lib}} = $rmax{$lib}\n";
            $rassigned{$lib} =~ m/^:(.*):$/;
            my @rassigned = sort { $a <=> $b } split( ":", $1 );
            print STDERR "  ", join(' ', @rassigned), "\n";
        }
        foreach my $lib ( keys %fmax ) {
            print STDERR "Max function code fmax{${lib}} = $fmax{$lib}\n";
            $fassigned{$lib} =~ m/^:(.*):$/;
            my @fassigned = sort { $a <=> $b } split( ":", $1 );
            print STDERR "  ", join(' ', @fassigned), "\n";
        }
    }
}

# Scan each header file in turn and make a list of error codes
# and function names

my $hdr;
my $lib;
while ( ( $hdr, $lib ) = each %libinc ) {
    next if $hdr eq "NONE";
    print STDERR "Scanning header file $hdr\n" if $debug;
    my $line = "";
    my $def = "";
    my $linenr = 0;
    my $cpp = 0;

    open(IN, "<$hdr") || die "Can't open $hdr, $!,";
    while ( <IN> ) {
        $linenr++;

        if ( $line ne '' ) {
            $_    = $line . $_;
            $line = '';
        }

        if ( /\\$/ ) {
            $line = $_;
            next;
        }

        if ( /\/\*/ ) {
            if ( not /\*\// ) {    # multiline comment...
                $line = $_;        # ... just accumulate
                next;
            } else {
                s/\/\*.*?\*\///gs;    # wipe it
            }
        }

        if ( $cpp ) {
            $cpp++ if /^#\s*if/;
            $cpp-- if /^#\s*endif/;
            next;
        }
        $cpp = 1 if /^#.*ifdef.*cplusplus/;    # skip "C" declaration

        next if /^\#/;    # skip preprocessor directives

        s/{[^{}]*}//gs;     # ignore {} blocks

        if ( /\{|\/\*/ ) {    # Add a } so editor works...
            $line = $_;
        } else {
            $def .= $_;
        }
    }

    # Delete any DECLARE_ macros
    my $defnr = 0;
    $def =~ s/DECLARE_\w+\([\w,\s]+\)//gs;
    foreach ( split /;/, $def ) {
        $defnr++;
        # The goal is to collect function names from function declarations.

        s/^[\n\s]*//g;
        s/[\n\s]*$//g;

        # Skip over recognized non-function declarations
        next if /typedef\W/ or /DECLARE_STACK_OF/ or /TYPEDEF_.*_OF/;

        # Remove STACK_OF(foo)
        s/STACK_OF\(\w+\)/void/;

        # Reduce argument lists to empty ()
        # fold round brackets recursively: (t(*v)(t),t) -> (t{}{},t) -> {}
        while ( /\(.*\)/s ) {
            s/\([^\(\)]+\)/\{\}/gs;
            s/\(\s*\*\s*(\w+)\s*\{\}\s*\)/$1/gs;    #(*f{}) -> f
        }

        # pretend as we didn't use curly braces: {} -> ()
        s/\{\}/\(\)/gs;

        if ( /(\w+)\s*\(\).*/s ) {    # first token prior [first] () is
            my $name = $1;          # a function name!
            $name =~ tr/[a-z]/[A-Z]/;
            $ftrans{$name} = $1;
        } elsif ( /[\(\)]/ and not(/=/) ) {
            print STDERR "Header $hdr: cannot parse: $_;\n";
        }
    }

    next if $reindex;

    if ( $lib eq "SSL" ) {
        if ( $rmax{$lib} >= 1000 ) {
            print STDERR
              "!! ERROR: SSL error codes 1000+ are reserved for alerts.\n";
            print STDERR "!!        Any new alerts must be added to $config.\n";
            $errors++;
            print STDERR "\n";
        }
    }
    close IN;
}

# Scan each C source file and look for function and reason codes
# This is done by looking for strings that "look like" function or
# reason codes: basically anything consisting of all upper case and
# numerics which has _F_ or _R_ in it and which has the name of an
# error library at the start.  This seems to work fine except for the
# oddly named structure BIO_F_CTX which needs to be ignored.
# If a code doesn't exist in list compiled from headers then mark it
# with the value "X" as a place holder to give it a value later.
# Store all function and reason codes found in %ufcodes and %urcodes
# so all those unreferenced can be printed out.

my %ufcodes;
my %urcodes;
foreach my $file ( @source ) {
    # Don't parse the error source file.
    next if exists $cskip{$file};
    print STDERR "Scanning $file\r" if $debug;
    open( IN, "<$file" ) || die "Can't open $file, $!,";
    my $func;
    my $linenr = 0;
    while ( <IN> ) {

        # skip obsoleted source files entirely!
        last if /^#error\s+obsolete/;
        $linenr++;
        if ( !/;$/ && /^\**([a-zA-Z_].*[\s*])?([A-Za-z_0-9]+)\(.*([),]|$)/ ) {
            /^([^()]*(\([^()]*\)[^()]*)*)\(/;
            $1 =~ /([A-Za-z_0-9]*)$/;
            $func = $1;
        }

        if ( /(([A-Z0-9]+)_F_([A-Z0-9_]+))/ ) {
            next unless exists $errorfile{$2};
            next if $1 eq "BIO_F_BUFFER_CTX";
            $ufcodes{$1} = 1;
            if ( !exists $fcodes{$1} ) {
                $fcodes{$1} = "X";
                $fnew{$2}++;
            }
            $ftrans{$3} = $func unless exists $ftrans{$3};
            if ( uc($func) ne $3 ) {
                print STDERR "ERROR: mismatch $file:$linenr $func:$3\n";
                $errors++;
            }
            print STDERR "Function: $1\t= $fcodes{$1} (lib: $2, name: $3)\n"
              if $debug;
        }
        if ( /(([A-Z0-9]+)_R_[A-Z0-9_]+)/ ) {
            next unless exists $errorfile{$2};
            $urcodes{$1} = 1;
            if ( !exists $rcodes{$1} ) {
                $rcodes{$1} = "X";
                $rnew{$2}++;
            }
            print STDERR "Reason: $1\t= $rcodes{$1} (lib: $2)\n" if $debug;
        }
    }
    close IN;
}
print "Done scanning sources                              \n" if $debug;

# Now process each library in turn.
my $newstate = 0;
foreach $lib ( keys %errorfile ) {

    if ( !$fnew{$lib} && !$rnew{$lib} ) {
        next unless $rebuild;
    }
    next unless $dowrite;
    print STDERR "$lib: $fnew{$lib} functions, $rnew{$lib} reasons.\n";
    $newstate = 1;

    # If we get here then we have some new error codes so we
    # need to rebuild the header file and C file.

    # Make a sorted list of error and reason codes for later use.
    my @function = sort grep( /^${lib}_/, keys %fcodes );
    my @reasons  = sort grep( /^${lib}_/, keys %rcodes );

    # Rewrite the header file

    my $hfile = $hinc{$lib};
    $hfile =~ s/.h$/err.h/ if $internal;
    open( OUT, ">$hfile" ) || die "Can't write to $hfile, $!,";
    print OUT <<"EOF";
/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the \"License\").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_${lib}_ERR_H
# define HEADER_${lib}_ERR_H

# ifdef  __cplusplus
extern \"C\" {
# endif

int ERR_load_${lib}_strings(void);
EOF
    if ( ! $internal ) {
        print OUT <<"EOF";
void ERR_unload_${lib}_strings(void);
void ERR_${lib}_error(int function, int reason, char *file, int line);

# define ${lib}err(f, r) ERR_${lib}_error((f), (r), OPENSSL_FILE, OPENSSL_LINE)

EOF
    }

    print OUT "\n/*\n * $lib function codes.\n */\n";
    foreach my $i ( @function ) {
        my $z = 48 - length($i);
        if ( $fcodes{$i} eq "X" ) {
            $fassigned{$lib} =~ m/^:([^:]*):/;
            my $findcode = $1;
            $findcode = $fmax{$lib} if !defined $findcode;
            while ( $fassigned{$lib} =~ m/:$findcode:/ ) {
                $findcode++;
            }
            $fcodes{$i} = $findcode;
            $fassigned{$lib} .= "$findcode:";
            print STDERR "New Function code $i\n" if $debug;
        }
        printf OUT "# define $i%s $fcodes{$i}\n", " " x $z;
    }

    print OUT "\n/*\n * $lib function codes.\n */\n";
    foreach my $i ( @reasons ) {
        my $z = 48 - length($i);
        if ( $rcodes{$i} eq "X" ) {
            $rassigned{$lib} =~ m/^:([^:]*):/;
            my $findcode = $1;
            $findcode = $rmax{$lib} if !defined $findcode;
            while ( $rassigned{$lib} =~ m/:$findcode:/ ) {
                $findcode++;
            }
            $rcodes{$i} = $findcode;
            $rassigned{$lib} .= "$findcode:";
            print STDERR "New Reason code $i\n" if $debug;
        }
        printf OUT "# define $i%s $rcodes{$i}\n", " " x $z;
    }
    print OUT "\n";

    print OUT "# ifdef  __cplusplus\n";
    print OUT "}\n";
    print OUT "# endif\n";
    print OUT "#endif\n";

    # Rewrite the C source file containing the error details.

    # First, read any existing reason string definitions:
    my %err_reason_strings;
    my $cfile = $errorfile{$lib};
    if ( open( IN, "<$cfile" ) ) {
        my $line = "";
        while ( <IN> ) {
            s|\R$||;    # Better chomp
            $_    = $line . $_;
            $line = "";
            if ( /{ERR_(PACK|FUNC|REASON)\(/ ) {
                if ( /\b(${lib}_R_\w*)\b.*\"(.*)\"/ ) {
                    $err_reason_strings{$1} = $2;
                } elsif ( /\b${lib}_F_(\w*)\b.*\"(.*)\"/ ) {
                    if ( !exists $ftrans{$1} && $1 ne $2 ) {
                        print STDERR "WARNING: Mismatched function string $2\n";
                        $ftrans{$1} = $2;
                    }
                } else {
                    $line = $_;
                }
            }
        }
        close(IN);
    }

    my $hincf;
    my $pack_errcode;
    if ( $internal ) {
        $hincf = "\"$hfile\"";
        $pack_errcode = "ERR_LIB_${lib}";
    } else {
        $hincf = $hfile;
        $hincf =~ s|.*include/||;
        if ( $hincf =~ m|^openssl/| ) {
            $hincf = "<${hincf}>";
        } else {
            $hincf = "\"${hincf}\"";
        }
        $pack_errcode = "0";
    }

    open( OUT, ">$cfile" )
        || die "Can't open $cfile for writing, $!, stopped";

    my $const = '';
    $const = 'const' if $internal;

    print OUT <<"EOF";
/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include $hincf

#ifndef OPENSSL_NO_ERR

static $const ERR_STRING_DATA ${lib}_str_functs[] = {
EOF

    # Add each function code: if a function name is found then use it.
    foreach my $i ( @function ) {
        my $fn;
        $i =~ /^${lib}_F_(\S+)$/;
        $fn = $1;
        $fn = $ftrans{$fn} if exists $ftrans{$fn};
        print OUT "    {ERR_PACK($pack_errcode, $i, 0),\n     \"$fn\"},\n";
    }
    print OUT <<"EOF";
    {0, NULL}
};

static $const ERR_STRING_DATA ${lib}_str_reasons[] = {
EOF

    # Add each reason code.
    foreach my $i ( @reasons ) {
        my $rn;
        if ( exists $err_reason_strings{$i} ) {
            $rn = $err_reason_strings{$i};
        } else {
            $i =~ /^${lib}_R_(\S+)$/;
            $rn = $1;
            $rn =~ tr/_[A-Z]/ [a-z]/;
        }
        print OUT "    {ERR_PACK($pack_errcode, 0, $i),\n    \"$rn\"},\n";
    }
    print OUT <<"EOF";
    {0, NULL}
};

#endif
EOF
    if ( $internal ) {
        print OUT <<"EOF";

int ERR_load_${lib}_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(${lib}_str_functs[0].error) == NULL) {
        ERR_load_strings_const(${lib}_str_functs);
        ERR_load_strings_const(${lib}_str_reasons);
    }
#endif
    return 1;
}
EOF
    } else {
        print OUT <<"EOF";

static int ${lib}_lib_error_code = 0;
static int ${lib}_error_loaded = 0;

int ERR_load_${lib}_strings(void)
{
    if (${lib}_lib_error_code == 0)
        ${lib}_lib_error_code = ERR_get_next_error_library();

    if (${lib}_error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(${lib}_lib_error_code, ${lib}_str_functs);
        ERR_load_strings(${lib}_lib_error_code, ${lib}_str_reasons);
#endif
        ${lib}_error_loaded = 1;
    }
    return 1;
}

void ERR_unload_${lib}_strings(void)
{
    if (${lib}_error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(${lib}_lib_error_code, ${lib}_str_functs);
        ERR_unload_strings(${lib}_lib_error_code, ${lib}_str_reasons);
#endif
        ${lib}_error_loaded = 0;
    }
}

void ERR_${lib}_error(int function, int reason, char *file, int line)
{
    if (${lib}_lib_error_code == 0)
        ${lib}_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(${lib}_lib_error_code, function, reason, file, line);
}
EOF

    }

    close OUT;
    undef %err_reason_strings;
}

# Make a list of unreferenced function and reason codes
if ( $unref ) {
    my @funref;
    foreach ( keys %fcodes ) {
        push( @funref, $_ ) unless exists $ufcodes{$_};
    }
    my @runref;
    foreach ( keys %rcodes ) {
        push( @runref, $_ ) unless exists $urcodes{$_};
    }
    if ( @funref ) {
        print STDERR "The following function codes were not referenced:\n";
        foreach ( sort @funref ) {
            print STDERR "  $_\n";
        }
    }
    if ( @runref ) {
        print STDERR "The following reason codes were not referenced:\n";
        foreach ( sort @runref ) {
            print STDERR "  $_\n";
        }
    }
}

die "Found $errors errors, quitting" if $errors;

# Update the state file
if ( $newstate )  {
    open(OUT, ">$statefile.new")
        || die "Can't write $statefile.new, $!";
    foreach my $i ( sort keys %fcodes ) {
        print "$i $fcodes{$i}\n";
    }
    foreach my $i ( sort keys %rcodes ) {
        print "$i $fcodes{$i}\n";
    }
    close(OUT);
    rename "$statefile", "$statefile.old"
        || die "Can't backup $statefile to $statefile.old, $!";
    rename "$statefile.new", "$statefile"
        || die "Can't rename $statefile to $statefile.new, $!";
}
exit;
