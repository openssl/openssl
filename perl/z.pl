#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;
use Benchmark;

$buf=('x' x (1024*1024));
$buf=('x' x (1024*1024));

@md=();
foreach $name ("md2", "mdc2", "sha", "ripemd160", "sha1", "md5")
	{
	if (($name eq "md2") || ($name eq "mdc2"))
		{ $num=5; }
	else	{ $num=100; }

	$t=timeit($num,'&hash($name)');
	printf "%6d000 bytes/sec:$name\n",int(($num*1024*1024)/$t->[1]/1000);
	}

sub hash
	{
	my($name)=@_;
	my($f,$digest);

	($f=MD->new($name)) ||
		die "$_ is an unknown message digest algorithm\n";
	$f->update($buf);
	$digest=$f->final();
	}

