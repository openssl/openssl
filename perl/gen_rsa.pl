#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$bits=512;
$bits=$ARGV[0] if $#ARGV >= 0;

$p=SSLeay::BN::generate_prime($bits/2,0,sub {print STDERR $_[0]?"+":"."});
print "\n";
$q=SSLeay::BN::generate_prime($bits/2,0,sub {print STDERR $_[0]?"+":"."});
print "\n";

$e=SSLeay::BN::hex2bn("10001");

$t1=$p-1;
$t2=$q-1;

($t1->gcd($e) == 1) || die "p failed the gcd test\n";
($t2->gcd($e) == 1) || die "q failed the gcd test\n";

($q,$p)=($p,$q) if ($p < $q);
$n=$p*$q;
$t=($p-1)*($q-1);
($t->gcd($e) == 1) || die "t failed the gcd test\n";

$d=$e->mod_inverse($t);

$dmp1=$d%($p-1);
$dmq1=$d%($q-1);
$iqmp=$q->mod_inverse($p);

print "n   =$n\n";
print "e   =$e\n";
print "d   =$d\n";
print "dmp1=$dmp1\n";
print "dmq1=$dmq1\n";
print "iqmp=$iqmp\n";

$a=SSLeay::BN::bin2bn("This is an RSA test");
print "Test with\n'".$a->bn2bin."' or\n$a\n";

$t1=$a->mod_exp($e,$n);
print "$t1\n";
$t2=$t1->mod_exp($d,$n);
print "'".$t2->bn2bin."'\n";


