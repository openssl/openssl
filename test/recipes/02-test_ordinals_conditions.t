#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Unit test for the condition field of an ordinals file.
#
# The condition is a boolean expression over feature names, and ',' is a
# synonym for '&&' so that every field written before the expression
# grammar existed parses unchanged.  These tests cover the grammar, the
# form written back to the file, and evaluation against a set of disabled
# features.  The round trip matters as much as the parse: a field that
# parses but is written back differently would rewrite every line of
# util/*.num that touched it.

use strict;
use warnings;

use OpenSSL::Test;
use OpenSSL::Ordinals;

setup("test_ordinals_conditions");

# [ condition, written form, [ disabled features ], expected availability ]
#
# The written form is compared against the condition itself where the two
# should agree, which is every field that predates the grammar.
my @tests = (
    # The legacy shapes.  These are what util/*.num holds today, and the
    # written form must be identical to the input or those files churn.
    [ '',                     '',                     [],          1 ],
    [ 'SRP',                  'SRP',                  [],          1 ],
    [ 'SRP',                  'SRP',                  ['SRP'],     0 ],
    [ 'DEPRECATED_3_0,SRP',   'DEPRECATED_3_0,SRP',   [],          1 ],
    [ 'DEPRECATED_3_0,SRP',   'DEPRECATED_3_0,SRP',   ['SRP'],     0 ],
    [ 'DEPRECATED_3_0,SRP',   'DEPRECATED_3_0,SRP',   ['EC'],      1 ],
    # A conjunction is written in the legacy comma form whatever the input
    # spelling, and sorted, which is how the files have always been written.
    [ 'SRP&&EC',              'EC,SRP',               [],          1 ],
    [ 'SRP,EC',               'EC,SRP',               ['EC'],      0 ],
    # Disjunction.
    [ 'ZLIB||BROTLI',         'ZLIB||BROTLI',         [],          1 ],
    [ 'ZLIB||BROTLI',         'ZLIB||BROTLI',         ['ZLIB'],    1 ],
    [ 'ZLIB||BROTLI',         'ZLIB||BROTLI',         ['ZLIB','BROTLI'], 0 ],
    # Negation.  A negated term is available when the feature is disabled,
    # which is the case the flat list could never express.
    [ '!TS',                  '!TS',                  [],          0 ],
    [ '!TS',                  '!TS',                  ['TS'],      1 ],
    [ 'EC&&!TS',              'EC&&!TS',              ['TS'],      1 ],
    [ 'EC&&!TS',              'EC&&!TS',              [],          0 ],
    # Precedence: '!' binds tighter than '&&', which binds tighter than
    # '||'.  Parentheses are kept only where they change the reading.
    # Disabling C is the case that separates the two groupings: read as
    # A||(B&&C) it stays available through A, read as (A||B)&&C it does not.
    [ 'A||B&&C',              'A||B&&C',              ['C'],       1 ],
    [ '(A||B)&&C',            '(A||B)&&C',            ['C'],       0 ],
    [ 'A||B&&C',              'A||B&&C',              ['A','C'],   0 ],
    [ '(A||B)&&C',            '(A||B)&&C',            ['A'],       1 ],
    [ '!(A||B)',              '!(A||B)',              ['A','B'],   1 ],
    [ '!(A||B)',              '!(A||B)',              ['A'],       0 ],
);

# Fields that must be rejected rather than quietly given a meaning.  A
# condition that parses loosely is worse than one that fails: it would be
# written back in a form the author did not intend.
my @malformed = (
    'A&&',
    'A||',
    '(A',
    'A)',
    'A B',
    'A,,B',
    '!',
    'A&&&B',
    '1A',
);

plan tests => scalar @tests * 2 + scalar @malformed + 2;

foreach my $test (@tests) {
    my ($condition, $written, $disabled, $expected) = @$test;
    my $item = item_with_condition($condition);
    my %disabled = map { $_ => 1 } @$disabled;

    is($item->condition(), $written, "'$condition' is written as '$written'");
    is($item->available(\%disabled) ? 1 : 0, $expected,
       "'$condition' with [@$disabled] disabled is "
       . ($expected ? "available" : "unavailable"));
}

foreach my $condition (@malformed) {
    ok(!defined eval { item_with_condition($condition); 1 },
       "'$condition' is rejected");
}

# The written form must be a fixed point, or a file would keep changing
# every time it was regenerated.
my $twice_stable = 1;
foreach my $test (@tests) {
    my $once = item_with_condition($test->[0])->condition();
    my $twice = item_with_condition($once)->condition();

    next if $once eq $twice;
    diag("'$test->[0]' written as '$once', then as '$twice'");
    $twice_stable = 0;
}
ok($twice_stable, "the written form is stable when parsed again");

# Features are reported whatever their position in the expression, since
# callers use them to recognise names rather than to judge availability.
is(join(',', item_with_condition('X||(Y&&!Z)')->features()), 'X,Y,Z',
   "features are collected from the whole expression");

sub item_with_condition {
    my $condition = shift;

    return OpenSSL::Ordinals::Item->new(
        source    => 'test',
        name      => 'test_symbol',
        type      => 'FUNCTION',
        number    => 1,
        version   => '4_1_0',
        exists    => 1,
        condition => $condition);
}
