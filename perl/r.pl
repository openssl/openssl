#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$bits=512;
$bits=$ARGV[0] if $#ARGV >= 0;

$q=SSLeay::BN::dec2bn("334533373942443239443435463034324139443635374634423531423146313742443038394230324138363038393539303745363034393946353346323345374537463935433635374238353245344341444241344138413244373443323338334431414134363244443532423243423133433537");

$p=SSLeay::BN::dec2bn("3338413942343132463534373734353742343636444439363131313131353843334536434330363934313646414132453044434138413630434631334134443046313735313632344131433437443642434436423642453234383046393732383538444139393131314339303743393939363744443235443332393332394543384630304634323646333735");
$pp=SSLeay::BN::generate_prime($bits/2,0,sub {print STDERR $_[0]?"+":"."});

printf $pp->is_prime."\n";
printf $p->is_prime."\n";
printf $q->is_prime."\n";
printf "p->length=%d\n",$p->num_bits;
printf "q->length=%d\n",$q->num_bits;
$bits=$p->num_bits+$q->num_bits;
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

print "<$a>\n";
$t1=$a->mod_exp($e,$n);
print ">$t1>\n";
$t2=$t1->mod_exp($d,$n);
print "<$t2>\n";


