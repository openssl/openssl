# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package TAP::Parser::OpenSSL;

# A TAP::Parser subclass with OpenSSL extras:
#
# - failure verbosity: on a failed (sub-)test, the buffered preceding
#   output is printed.  Controlled by environment variables:
#     HARNESS_VERBOSE                everything is printed anyway
#     HARNESS_VERBOSE_FAILURE        (default) failed sub-test context
#     HARNESS_VERBOSE_FAILURE_PROGRESS
#                                    like the above, plus a progress
#                                    report on succeeded sub-tests
# - TAP copy: if HARNESS_TAP_COPY is set, all TAP output is copied to
#   the file it names.
# - AddressSanitizer "Indirect leak" output is grouped for GitHub
#   Actions log presentation.
#
# This used to live inline in test/run_tests.pl; it now stands alone so
# it can be used with a plain 'prove' invocation.

use strict;
use warnings;

use parent -norequire, 'TAP::Parser';
require TAP::Parser;

my $failure_verbosity = $ENV{HARNESS_VERBOSE} ? 0 :
    $ENV{HARNESS_VERBOSE_FAILURE_PROGRESS} ? 2 :
    1; # $ENV{HARNESS_VERBOSE_FAILURE}

my $tap_copy_fh;
if (defined $ENV{HARNESS_TAP_COPY}) {
    open $tap_copy_fh, ">", $ENV{HARNESS_TAP_COPY}
        or die "Trying to create $ENV{HARNESS_TAP_COPY}: $!\n";
}

sub new {
    my $class = shift;
    my %opts = %{ shift() };
    my @plans = (); # initial level, no plan yet
    my $output_buffer = "";
    my $in_indirect = 0;

    # We rely heavily on perl closures to make failure verbosity work
    # We need to do so, because there's no way to safely pass extra
    # objects down all the way to the TAP::Parser::Result object
    my @failure_output = ();
    my %callbacks = ();
    if ($failure_verbosity > 0 || defined $tap_copy_fh) {
        $callbacks{ALL} = sub { # on each line of test output
            my $self = shift;
            print $tap_copy_fh $self->as_string, "\n"
                if defined $tap_copy_fh;

            if ($failure_verbosity > 0) {
                my $is_plan = $self->is_plan;
                my $tests_planned = $is_plan && $self->tests_planned;
                my $is_test = $self->is_test;
                my $is_ok = $is_test && $self->is_ok;

                # workaround for parser not coping with sub-test indentation
                if ($self->is_unknown) {
                    my $level = $#plans;
                    my $indent = $level < 0 ? "" : " " x ($level * 4);

                    ($is_plan, $tests_planned) = (1, $1)
                        if ($self->as_string =~ m/^$indent    1\.\.(\d+)/);
                    ($is_test, $is_ok) = (1, !$1)
                        if ($self->as_string =~ m/^$indent(not )?ok /);
                }

                if ($is_plan) {
                    push @plans, $tests_planned;
                    $output_buffer = ""; # ignore comments etc. until plan
                } elsif ($is_test) { # result of a test
                    pop @plans if @plans && --($plans[-1]) <= 0;
                    if ($output_buffer =~ /.*Indirect leak of.*/ == 1) {
                        my @asan_array = split("\n", $output_buffer);
                        foreach (@asan_array) {
                            if ($_ =~ /.*Indirect leak of.*/ == 1) {
                                if ($in_indirect != 1) {
                                    print "::group::Indirect Leaks\n";
                                }
                                $in_indirect = 1;
                            }
                            print "$_\n";
                            if ($_ =~ /.*Indirect leak of.*/ != 1) {
                                if ($_ =~ /^    #.*/ == 0) {
                                    if ($in_indirect != 0) {
                                        print "\n::endgroup::\n";
                                    }
                                    $in_indirect = 0;
                                }
                            }
                        }
                    } else {
                        print $output_buffer if !$is_ok;
                    }
                    print "\n".$self->as_string
                        if !$is_ok || $failure_verbosity == 2;
                    print "\n# ------------------------------------------------------------------------------" if !$is_ok;
                    $output_buffer = "";
                } elsif ($self->as_string ne "") {
                    # typically is_comment or is_unknown
                    $output_buffer .= "\n".$self->as_string;
                }
            }
        }
    }

    if ($failure_verbosity > 0) {
        $callbacks{EOF} = sub {
            my $self = shift;

            # We know we are a TAP::Parser::Aggregator object
            if (scalar $self->failed > 0 && @failure_output) {
                # We add an extra empty line, because in the case of a
                # progress counter, we're still at the end of that progress
                # line.
                print $_, "\n" foreach (("", @failure_output));
            }
            # Echo any trailing comments etc.
            print "$output_buffer";
        };
    }

    if (keys %callbacks) {
        # If %opts already has a callbacks element, the order here
        # ensures we do not override it
        %opts = ( callbacks => { %callbacks }, %opts );
    }

    return $class->SUPER::new({ %opts });
}

1;
