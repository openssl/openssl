#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Characterisation test for OpenSSL::ParseC.
#
# The fixtures in 02-test_parsec_data/ are run through the parser and the
# result is compared against a recorded transcript, expected.txt.  The
# transcript records what the parser does today, not what it ought to do:
# it exists so that a change to ParseC shows up as a reviewable diff of
# parser output rather than as a claim in a commit message.
#
# When a change to ParseC is intended to alter the output, regenerate the
# transcript and review the diff as part of the change:
#
#     OPENSSL_PARSEC_REGEN=1 make test TESTS=test_parsec
#
# Cases believed to be incorrect should additionally be asserted below
# under TODO (declaring `our $TODO;` for Test::More), so that the intent
# is recorded next to the behaviour.  A TODO that starts passing is
# reported by the harness and should be promoted to a plain assertion in
# the same change that fixes it.

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file);
use OpenSSL::ParseC;

setup("test_parsec");

# Fixtures are listed rather than globbed so that the transcript order is
# stable regardless of directory traversal order.
my @fixtures = qw(conditions.h declarations.h deprecation.h polarity.h);

plan tests => 11;

my %conds = ();
my @warnings = ();
my @transcript = ();

foreach my $fixture (@fixtures) {
    my @lines = read_fixture(data_file($fixture));

    @warnings = ();
    push @transcript, "### $fixture",
        render(parse_lines($fixture, @lines)), @warnings;
}

# The transcript is compared as a single string so that a mismatch is
# reported as one diff rather than as a cascade of failures.
my $got = join("\n", @transcript) . "\n";
my $expected_file = data_file("expected.txt");

if ($ENV{OPENSSL_PARSEC_REGEN}) {
    open(my $fh, '>', $expected_file)
        or die "Couldn't write $expected_file: $!\n";
    print $fh $got;
    close $fh;
    diag("regenerated $expected_file");
}

my $want = do {
    open(my $fh, '<', $expected_file)
        or die "Couldn't open $expected_file: $!\n";
    local $/ = undef;
    <$fh>;
};

ok(compare_transcript($got, $want), "parser output matches recorded transcript");

# Line endings must not change the parse.  Rather than commit a fixture
# with CRLF endings, which git and editors both like to normalise, the
# CRLF form is produced here and compared against the LF form.
my @lf = render(parse_lines('conditions.h',
                            read_fixture(data_file('conditions.h'))));
my @crlf = render(parse_lines('conditions.h',
                              map { my $l = $_; $l =~ s/\n\z/\r\n/; $l }
                              read_fixture(data_file('conditions.h'))));

is(join("\n", @crlf), join("\n", @lf),
   "CRLF line endings parse identically to LF");

# A deprecation guard is one term of a compound condition here.  ParseC
# used to rewrite such guard lines into the ordinals spelling before its
# generic condition handling ran, and because the rewrite replaced the
# whole line, the sibling terms were discarded.  The rewrite is gone and
# the generic handling now sees these lines like any other, so the
# siblings survive.
#
# These assert only that the sibling condition survives, deliberately not
# naming the deprecation spelling, which is the transcript's business.
ok(cond_mentions('dep_guard_and', 'OPENSSL_NO_TS'),
   "dep_guard_and retains OPENSSL_NO_TS");
ok(cond_mentions('dep_guard_and_reversed', 'OPENSSL_NO_TS'),
   "dep_guard_and_reversed retains OPENSSL_NO_TS");

# A compound condition keeps every term, whatever mix of polarities it is
# written with.  These name the sibling condition only, leaving the
# spelling to the transcript.
ok(cond_mentions('mixed_positive_first', 'OPENSSL_NO_COMP'),
   "mixed_positive_first retains OPENSSL_NO_COMP");
ok(cond_mentions('mixed_negative_first', 'OPENSSL_USE_NODELETE'),
   "mixed_negative_first retains OPENSSL_USE_NODELETE");
ok(cond_mentions('style_md_worked_example', 'OPENSSL_NO_HOOBLA'),
   "STYLE.md's worked example retains its nested disjunction");

# A level joined by '||' is one condition.  Several would be read as a
# conjunction downstream, where disabling one of the two drops a symbol the
# header declares.
is(scalar @{$conds{uniform_or_positive} // []}, 1,
   "a disjunction is one condition, not a list read as a conjunction");

# #else negates the level's condition as a whole.  !(A&&B) is a
# disjunction, which inverting term by term would turn into a conjunction.
is(scalar @{$conds{cond_else_over_and_otherwise} // []}, 1,
   "#else over a compound condition inverts it as a whole");

# A term the parser cannot represent weakens the condition and never
# strengthens it.  A conjunct costs only itself; a disjunct cannot go
# alone, since what remained would omit a symbol the header declares.
ok(cond_mentions('cond_opaque_conjunct', 'OPENSSL_NO_TS'),
   "an unrepresentable conjunct costs only itself");
is(scalar @{$conds{cond_opaque_disjunct} // []}, 0,
   "an unrepresentable disjunct costs the whole disjunction");

sub read_fixture {
    my $filename = shift;

    open(my $fh, '<', $filename) or die "Couldn't open $filename: $!\n";
    my @lines = <$fh>;
    close $fh;

    return @lines;
}

# Parse one fixture and remember each entry's conditions by name, for the
# benefit of the targeted assertions above.
#
# Warnings are deliberately left enabled and captured.  ParseC warns when
# it has had to drop a term of a preprocessor expression to arrive at a
# condition it can represent; that warning is the parser announcing that
# the condition it recorded is weaker than the one in the header.
# util/mknum.pl is invoked from the build with --no-warnings, so these are
# not seen in practice, which is exactly why the transcript should carry
# them.
sub parse_lines {
    my ($fixture, @lines) = @_;
    my @entries;

    {
        local $SIG{__WARN__} = sub {
            my $text = shift;

            $text =~ s/\s+/ /g;
            $text =~ s/ \z//;
            push @warnings, "W|$text";
        };
        @entries = parse(@lines, { filename => $fixture, warnings => 1 });
    }

    foreach my $entry (@entries) {
        $conds{$entry->{name}} = [ @{$entry->{conds} // []} ]
            if defined $entry->{name};
    }

    return @entries;
}

# One line per entry, pipe separated.  Fixed-width columns would re-align
# the whole transcript whenever a name grew, turning a one-entry change
# into a whole-file diff.
sub render {
    my @entries = @_;
    my @rendered = ();

    foreach my $entry (@entries) {
        my @fields = ($entry->{type} // '',
                      $entry->{name} // '',
                      $entry->{returntype} // '',
                      join(',', @{$entry->{conds} // []}),
                      $entry->{value} // '');

        foreach my $field (@fields) {
            $field =~ s/\s+/ /g;
            $field =~ s/^ //;
            $field =~ s/ \z//;
        }
        push @rendered, join('|', @fields);
    }

    return @rendered;
}

sub cond_mentions {
    my ($name, $wanted) = @_;

    return 0 unless defined $conds{$name};

    return scalar grep { index($_, $wanted) >= 0 } @{$conds{$name}};
}

# Report the first few differing lines rather than dumping both
# transcripts, which are long enough to bury the change.
sub compare_transcript {
    my ($got_text, $want_text) = @_;

    return 1 if $got_text eq $want_text;

    my @got_lines = split(/\n/, $got_text, -1);
    my @want_lines = split(/\n/, $want_text, -1);
    my $reported = 0;

    for (my $i = 0; $i < @got_lines || $i < @want_lines; $i++) {
        my $g = $i < @got_lines ? $got_lines[$i] : '(no line)';
        my $w = $i < @want_lines ? $want_lines[$i] : '(no line)';

        next if $g eq $w;
        diag(sprintf("line %d:\n  recorded: %s\n  parsed:   %s",
                     $i + 1, $w, $g));
        last if ++$reported >= 10;
    }
    diag("regenerate with OPENSSL_PARSEC_REGEN=1 if the change is intended");

    return 0;
}
