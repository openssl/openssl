#!/usr/bin/env perl
# Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw/catdir catfile/;
use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file result_dir/;
use OpenSSL::Test::Utils;

my $fuzzer = "hashtable";
setup("test_fuzz_${fuzzer}");

plan tests => 2; # one more due to below require_ok(...)

require_ok(srctop_file('test','recipes','fuzz.pl'));

# The size of a record of fuzz/hashtable.c
my $record = 11;

sub read_input {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "$path: $!";
    binmode $fh;
    local $/;
    my $input = <$fh>;
    close $fh;
    return $input;
}

sub write_input {
    my ($path, $input) = @_;
    open(my $fh, '>', $path) or die "$path: $!";
    binmode $fh;
    print $fh $input;
    close $fh or die "$path: $!";
}

# The corpus is that of the ossl_ht fuzzer, which took one record per input
# and kept its table from one input to the next. This fuzzer starts every
# input with empty tables, so such an input is one operation on tables that
# hold nothing. Run the corpus together with one more input: the records of
# all the others in a row, which meet what the earlier ones left in the tables.
sub chained_corpus {
    my ($src) = @_;
    my $dst = catdir(result_dir(), 'corpus');
    my $chain = '';

    opendir(my $dh, $src) or return;
    my @names = sort grep { -f catfile($src, $_) } readdir($dh);
    closedir($dh);

    mkdir $dst or die "$dst: $!";
    foreach my $name (@names) {
        my $input = read_input(catfile($src, $name));
        write_input(catfile($dst, $name), $input);
        # whole records only, so that the next input starts at a record
        $chain .= substr($input, 0, length($input) - length($input) % $record);
    }
    write_input(catfile($dst, 'all-records'), $chain) if $chain ne '';
    return $dst;
}

my $corpus = chained_corpus(srctop_dir('fuzz', 'corpora', $fuzzer));

# without a corpus, as when its submodule is not checked out, this skips
fuzz_ok($fuzzer, defined $corpus ? (corpus => $corpus) : ());
