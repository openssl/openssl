#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$md=SSLeay::MD::new("md5");

foreach (@SSLeay::Cipher::names)
	{
	($c=SSLeay::Cipher::new($_)) ||
		die "'$_' is an unknown cipher algorithm\n";


	$data="012345678abcdefghijklmnopqrstuvwxyz";
	$c->init("01234567abcdefghABCDEFGH","zyxwvut",1);

	$in =$c->update(substr($data, 0, 5));
	$in.=$c->update(substr($data, 5,10));
	$in.=$c->update(substr($data,15,1));
	$in.=$c->update(substr($data,16));

	$in.=$c->final();

	$c->init("01234567abcdefghABCDEFGH","zyxwvut",0);
	$out=$c->update($in);
	$out.=$c->final();

	($out eq $data) || die "decrypt for $_ failed:$!\n";

	$md->init();
	$md->update($in);
	$digest=$md->final();

	print unpack("H*",$digest);
	printf " %2d %2d %2d %s\n", $c->key_length(), $c->iv_length(),
		$c->block_size(), $c->name();
	}

