#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

for (7 .. 7926)
	{
	my $num = SSLeay::BN::dec2bn($_);
	print "$_ is ".($num->is_prime ? 'prime' : 'composite'), "\n";
	}
