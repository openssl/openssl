#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

# 2687145 * 3003 * 10^5072 - 1. 

$a=SSLeay::BN::set_word(2687145);
$b=SSLeay::BN::set_word(3003);
$c=SSLeay::BN::set_word(10);
$d=SSLeay::BN::set_word(5072);
$e=SSLeay::BN::set_word(1);

print $a->bn2hex()."\n";
print $b->bn2hex()."\n";
print $c->bn2hex()."\n";
print $d->bn2hex()."\n";
print $e->bn2hex()."\n";

$f=(($a->mul($b)->mul($c->exp($d)))->sub($e));
#print "$a $b\n";

$c=$a->mul($b);
print "1->".$c->bn2hex()." \n";

$c=$a*$b;
print "2->".$c->bn2hex()." \n";
$a*=$b;
print "3->$a\n";

print $f->bn2hex()." $a\n";
print $a."\n";

print "$a=(($b*$c)/$d);\n";
$a=(($b*$c)/$d);
print "$a\n";

