#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

@md=();
($c=SSLeay::Cipher::new("idea")) ||
	die "'des' is an unknown cipher algorithm\n";

printf "name      =%s\n" ,$c->name();
printf "key length=%2d\n",$c->key_length();
printf "iv length =%2d\n",$c->iv_length();
printf "block size=%2d\n",$c->block_size();

$data="1234";
$c->init("01234567","abcdefgh",1);
$in=$c->update($data);
$in.=$c->final();

$c->init("01234567","abcdefgh",0);
$out=$c->update($in);
$out.=$c->final();
print $data;
print " -> ";
print $out;
print "\n";

