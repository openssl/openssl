#!/usr/bin/perl

use ExtUtils::testlib;

use SSLeay;

$data=<>;

#$b=SSLeay::BN::hex2bn($a);
#$data=$b->bn2bin;

#substr($data,0,8)="";
#print $data;

$md=SSLeay::MD::new("md5");
$md->init();
$md->update("test");
$key=$md->final();

$rc4=SSLeay::Cipher::new("rc4");
$rc4->init($key,"",1);
$out=$rc4->cipher($data);

print $out;

