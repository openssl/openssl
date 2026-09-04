#! /usr/bin/env perl
# Copyright 2020-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Math::BigInt;

use OpenSSL::Test qw(:DEFAULT data_file);
use OpenSSL::Test;

setup("test_prime");

plan tests => 19;

my $prime_file      = data_file("prime.txt");
my $composite_file  = data_file("composite.txt");
my $long_number_file = data_file("long_number.txt");
my $short_number_file = data_file("short_number.txt");
my $non_number_file  = data_file("non_number.txt");
my $hex_number_file  = data_file("hex_number.txt");
my $multiple_lines_file  = data_file("multiple_lines.txt");
my $empty_file  = data_file("empty.txt");


ok(run(app(["openssl", "prime", "-in", $prime_file])),
   "Run openssl prime with prime number -in file");

ok(run(app(["openssl", "prime", "-in", $composite_file])),
   "Run openssl prime with composite number -in file");

ok(run(app(["openssl", "prime", "-in", $long_number_file])),
   "Run openssl prime with long number -in file");

ok(run(app(["openssl", "prime", "-in", $short_number_file])),
   "Run openssl prime with a short number -in file");

ok(run(app(["openssl", "prime", "-in", $non_number_file])),
   "Run openssl prime with non number -in file");

ok(run(app(["openssl", "prime", "-in", "-hex", $hex_number_file])),
   "Run openssl prime with hex number -in file");

ok(run(app(["openssl", "prime", "-in", $multiple_lines_file])),
   "Run openssl prime with -in file with multiple lines");

ok(run(app(["openssl", "prime", "-in", $empty_file])),
   "Run openssl prime with an empty -in file");

ok(run(app(["openssl", "prime", "-in", $prime_file, $composite_file, $long_number_file, $multiple_lines_file])),
   "Run openssl prime with multiple -in files");

ok(run(app(["openssl", "prime", "-in", "does_not_exist.txt"])),
   "Run openssl prime with -in file that does not exist");

my @generated = run(app(["openssl", "prime", "-generate", "-bits", "128"]),
                    capture => 1);
chomp @generated;

ok(@generated == 1 && $generated[0] =~ /^\d+$/,
   "Run openssl prime -generate with decimal output");

ok(is_reported_prime($generated[0]),
   "Generated decimal number is prime");

@generated = run(app(["openssl", "prime", "-generate", "-bits", "128", "-hex"]),
                 capture => 1);
chomp @generated;

ok(@generated == 1 && $generated[0] =~ /^[89A-F][0-9A-F]{31}$/,
   "Run openssl prime -generate with 128 bit hex output");

ok(is_reported_prime($generated[0], "-hex"),
   "Generated hex number is prime");

@generated = run(app(["openssl", "prime", "-generate", "-bits", "128", "-safe"]),
                 capture => 1);
chomp @generated;

ok(@generated == 1 && $generated[0] =~ /^\d+$/,
   "Run openssl prime -generate with -safe");

ok(is_reported_prime($generated[0]),
   "Generated safe prime is prime");

my $q = @generated == 1
    ? Math::BigInt->new($generated[0])->bsub(1)->bdiv(2)->bstr() : "0";
ok(is_reported_prime($q),
   "Generated safe prime (p-1)/2 is prime");

ok(!run(app(["openssl", "prime", "-generate"])),
   "Run openssl prime -generate without -bits fails");

ok(!run(app(["openssl", "prime", "-generate", "-bits", "128", "42"])),
   "Run openssl prime -generate with a number argument fails");

# Check that the app reports the given number as prime.
sub is_reported_prime {
    my ($num, @flags) = @_;
    my @out = run(app(["openssl", "prime", @flags, $num // "0"]),
                  capture => 1);
    return scalar grep { / is prime$/ } @out;
}
