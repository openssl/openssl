#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

for ($i=1; $i<1000; $i++)
	{
	$a.=$i%10;
	$y=SSLeay::BN::dec2bn($a);
	$z=SSLeay::BN::bn2dec($y);

	print "$a\n$y\n$z\n";
	}

