#!/usr/local/bin/perl
use ExtUtils::testlib;
use SSLeay;

$num=SSLeay::BN::new();
$shift=SSLeay::BN::new();

print "0\n";
$num=SSLeay::BN::hex2bn("1234329378209857309429670349760347603497603496398");
print "1\n";
$s=SSLeay::BN::hex2bn("59");
print "a\n";
$r=$num->lshift(59);
print "b";

print $num->bn2hex."\n";
print $s->bn2hex."\n";
print $r->bn2hex."\n";
