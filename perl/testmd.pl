#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

@md=();
foreach ("md2", "md5", "sha", "sha1", "mdc2", "ripemd160")
	{
	($f=MD->new($_)) ||
		die "$_ is an unknown message digest algorithm\n";
	push(@md,$f);
	}

while (<>)
	{
	foreach $md (@md)
		{ $md->update($_); }
	}

foreach (@md)
	{
	$digest=$_->final();
	printf "%-4s=%s\n",$_->name(),unpack("H*",$digest);
	}

