#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$a=SSLeay::BN::dec2bn("1231353465324563455");
print "a=$a\n".$a->bn2dec."\n";
$b=SSLeay::BN::dec2bn("98790816238765235");
print "a=$a\nb=$b\n";
print $a->gcd($b)."\n";

