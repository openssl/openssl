#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

@md=();
($c=SSLeay::Cipher::new("idea")) ||
	die "'des' is an unknown cipher algorithm\n";

$key=" ";
$iv=" ";
$c->init($key,$iv,0);
while (<>)
	{
	print $c->update($_);
	}
print $c->final();

