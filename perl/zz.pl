#!/usr/local/bin/perl
use ExtUtils::testlib;
use SSLeay;

$a=SSLeay::BN::dec2bn("12345678901234567890");
$b=SSLeay::BN::dec2bn("98765432109876543210");
print "a=$a\n";
print "b=$b\n";

$n=$a*$b;
$m=$n+"1223123235345634764534567889";
$l=$m*88888888;

$r=$l/$b;

print "a=$a\n";
print "b=$b\n";
print "n=$n\n";
print "m=$m\n";
print "l=$l\n";
print "r=$r\n";

