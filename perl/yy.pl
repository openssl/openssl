#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$a=SSLeay::BN::new();

$a+="1234567";

print $a->bn2hex()."\n";


for (1 .. 20)
	{
	$a*=$a;
	$b=$a->bn2hex();
	print " ".$b."\n".length($b)."\n";
	}
