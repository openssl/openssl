#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

# 2687145 * 3003 * 10^5072 - 1. 

$a=SSLeay::BN::set_word(99);
$b=SSLeay::BN::set_word(100);

$aa=$a->dup;
$bb=$b->dup;

$c=$a*$b;
$bb+=$a;

print "$a*$b=$c\n";
print "$bb\n";
