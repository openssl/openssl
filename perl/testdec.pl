#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$a=SSLeay::BN::dec2bn("1234");

foreach (1..4)
	{
	$a*=$a;
	print $a."\n",$a->bn2dec()."\n";
	}

