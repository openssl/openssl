#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

# Recognise VERBOSE and V which is common on other projects.
# Additionally, also recognise VERBOSE_FAILURE and VF.
BEGIN {
    $ENV{HARNESS_VERBOSE} = "yes" if $ENV{VERBOSE} || $ENV{V};
    $ENV{HARNESS_VERBOSE_FAILURE} = "yes" if $ENV{VERBOSE_FAILURE} || $ENV{VF};
}

use File::Spec::Functions qw/catdir catfile curdir abs2rel rel2abs/;
use File::Basename;
use FindBin;
use lib "$FindBin::Bin/../util/perl";
use OpenSSL::Glob;

my $srctop = $ENV{SRCTOP} || $ENV{TOP};
my $bldtop = $ENV{BLDTOP} || $ENV{TOP};
my $recipesdir = catdir($srctop, "test", "recipes");
my $libdir = rel2abs(catdir($srctop, "util", "perl"));

$ENV{OPENSSL_CONF} = catdir($srctop, "apps", "openssl.cnf");

my %tapargs =
    ( verbosity         => $ENV{HARNESS_VERBOSE} ? 1 : 0,
      lib               => [ $libdir ],
      switches          => '-w',
      merge             => 1,
    );

# Additional OpenSSL special TAP arguments.  Because we can't pass them via
# TAP::Harness->new(), they will be accessed directly, see the
# TAP::Parser::OpenSSL implementation further down
my %openssl_args = ();

$openssl_args{'failure_verbosity'} =
    $ENV{HARNESS_VERBOSE_FAILURE} && $tapargs{verbosity} < 1 ? 1 : 0;

my $outfilename = $ENV{HARNESS_TAP_COPY};
open $openssl_args{'tap_copy'}, ">$outfilename"
    or die "Trying to create $outfilename: $!\n"
    if defined $outfilename;

my @alltests = find_matching_tests("*");
my %tests = ();

my $initial_arg = 1;
foreach my $arg (@ARGV ? @ARGV : ('alltests')) {
    if ($arg eq 'list') {
	foreach (@alltests) {
	    (my $x = basename($_)) =~ s|^[0-9][0-9]-(.*)\.t$|$1|;
	    print $x,"\n";
	}
	exit 0;
    }
    if ($arg eq 'alltests') {
	warn "'alltests' encountered, ignoring everything before that...\n"
	    unless $initial_arg;
	%tests = map { $_ => basename($_) } @alltests;
    } elsif ($arg =~ m/^(-?)(.*)/) {
	my $sign = $1;
	my $test = $2;
	my @matches = find_matching_tests($test);

	# If '-foo' is the first arg, it's short for 'alltests -foo'
	if ($sign eq '-' && $initial_arg) {
	    %tests = map { $_ => basename($_) } @alltests;
	}

	if (scalar @matches == 0) {
	    warn "Test $test found no match, skipping ",
		($sign eq '-' ? "removal" : "addition"),
		"...\n";
	} else {
	    foreach $test (@matches) {
		if ($sign eq '-') {
		    delete $tests{$test};
		} else {
		    $tests{$test} = basename($test);
		}
	    }
	}
    } else {
	warn "I don't know what '$arg' is about, ignoring...\n";
    }

    $initial_arg = 0;
}

sub find_matching_tests {
    my ($glob) = @_;

    if ($glob =~ m|^[\d\[\]\?\-]+$|) {
        return glob(catfile($recipesdir,"$glob-*.t"));
    }
    return glob(catfile($recipesdir,"*-$glob.t"));
}

# The following is quite a bit of hackery to adapt to both TAP::Harness
# and Test::Harness, depending on what's available.
# The TAP::Harness hack allows support for HARNESS_VERBOSE_FAILURE and
# HARNESS_TAP_COPY, while the Test::Harness hack can't, because the pre
# TAP::Harness Test::Harness simply doesn't have support for this sort of
# thing.
#
# We use eval to avoid undue interruption if TAP::Harness isn't present.

my $package;
my $eres;

$eres = eval {
    package TAP::Parser::OpenSSL;
    use parent 'TAP::Parser';

    sub new {
        my $class = shift;
        my %opts = %{ shift() };

        # We rely heavily on perl closures to make failure verbosity work
        # We need to do so, because there's no way to safely pass extra
        # objects down all the way to the TAP::Parser::Result object
        my @failure_output = ();
        my %callbacks = ();
        if ($openssl_args{failure_verbosity}
            || defined $openssl_args{tap_copy}) {
            $callbacks{ALL} = sub {
                my $self = shift;
                my $fh = $openssl_args{tap_copy};

                print $fh $self->as_string, "\n"
                    if defined $fh;
                push @failure_output, $self->as_string
                    if $openssl_args{failure_verbosity} > 0;
            };
        }

        if ($openssl_args{failure_verbosity} > 0) {
            $callbacks{EOF} = sub {
                my $self = shift;

                # We know we are a TAP::Parser::Aggregator object
                if (scalar $self->failed > 0 && @failure_output) {
                    # We add an extra empty line, because in the case of a
                    # progress counter, we're still at the end of that progress
                    # line.
                    print $_, "\n" foreach (("", @failure_output));
                }
            };
        }

        if (keys %callbacks) {
            # If %opts already has a callbacks element, the order here
            # ensures we do not override it
            %opts = ( callbacks => { %callbacks }, %opts );
        }

        return $class->SUPER::new({ %opts });
    }

    package TAP::Harness::OpenSSL;
    use parent 'TAP::Harness';

    package main;

    $tapargs{parser_class} = "TAP::Parser::OpenSSL";
    $package = 'TAP::Harness::OpenSSL';
};

unless (defined $eres) {
    $eres = eval {
        # Fake TAP::Harness in case it's not loaded
        package TAP::Harness::fake;
        use parent 'Test::Harness';

        sub new {
            my $class = shift;
            my %args = %{ shift() };

            return bless { %args }, $class;
        }

        sub runtests {
            my $self = shift;

            # Pre TAP::Harness Test::Harness doesn't support [ filename, name ]
            # elements, so convert such elements to just be the filename
            my @args = map { ref($_) eq 'ARRAY' ? $_->[0] : $_ } @_;

            my @switches = ();
            if ($self->{switches}) {
                push @switches, $self->{switches};
            }
            if ($self->{lib}) {
                foreach (@{$self->{lib}}) {
                    my $l = $_;

                    # It seems that $switches is getting interpreted with 'eval'
                    # or something like that, and that we need to take care of
                    # backslashes or they will disappear along the way.
                    $l =~ s|\\|\\\\|g if $^O eq "MSWin32";
                    push @switches, "-I$l";
                }
            }

            $Test::Harness::switches = join(' ', @switches);
            Test::Harness::runtests(@args);
        }

        package main;
        $package = 'TAP::Harness::fake';
    };
}

unless (defined $eres) {
    print $@,"\n" if $@;
    print $!,"\n" if $!;
    exit 127;
}

my $harness = $package->new(\%tapargs);
my $ret =
    $harness->runtests(map { [ abs2rel($_, rel2abs(curdir())), $tests{$_} ] }
                       sort keys %tests);

# $ret->has_errors may be any number, not just 0 or 1.  On VMS, numbers
# from 2 and on are used as is as VMS statuses, which has severity encoded
# in the lower 3 bits.  0 and 1, on the other hand, generate SUCCESS and
# FAILURE, so for currect reporting on all platforms, we make sure the only
# exit codes are 0 and 1.  Double-bang is the trick to do so.
exit !!$ret->has_errors if (ref($ret) eq "TAP::Parser::Aggregator");

# If this isn't a TAP::Parser::Aggregator, it's the pre-TAP test harness,
# which simply dies at the end if any test failed, so we don't need to bother
# with any exit code in that case.
