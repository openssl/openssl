#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

($a=SSLeay::BN::new()) || die "unable to make bignum\n";
($b=SSLeay::BN::new()) || die "unable to make bignum\n";

$a=SSLeay::BN::hex2bn("123456789ABCDEF");
$b=SSLeay::BN::hex2bn("123456789ABCDEF");
$mod=SSLeay::BN::hex2bn("fedcba9876543201");
$c=SSLeay::BN::hex2bn("1234");

print "a=".$a->bn2hex()."\n";
print "b=".$b->bn2hex()."\n";
print "c=".$c->bn2hex()."\n";

print $a->mul($b)->bn2hex."\n";
($d,$r)=$b->div($c);
print "($d)($r)\n";
printf "%s x %s + %s\n",$c->bn2hex,$d->bn2hex,$r->bn2hex;

$g=$d;

for (;;)
	{
	$a=$a->mod_mul($a,$mod);
	print $a->bn2hex."\n";
	}
