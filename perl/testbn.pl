#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$num ="a43f6a8885a308d313198a2e03707344a4093822";
$num.="299f31d0082efa98ec4e6c89452821e638d01377";
$num.="be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5";
$num.="b54709179216d5d98979fb1bd1310ba698dfb5ac";
$num.="2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045";
$num.="f12c7f9924a19947b3916cf70801f2e2858efc16";
$num.="636920d871574e69a458fea3f4933d7e0d95748f";
$num.="728eb658718bcd5882154aee7b54a41dc25a59b5";
$num.="9c30d5392af26013c5d1b023286085f0ca417918";
$num.="b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3e";
$num.="d71577c1bd314b2778af2fda55605c60e65525f3";
$num.="aa55ab945748986263e8144055ca396a2aab10b6";
$num.="b4cc5c341141e8cea15486af7c8f14a7";

$a=SSLeay::BN::hex2bn($num);
print "num bits =".$a->num_bits."\n";
print $a->is_prime(50,sub {print STDERR $_[0]?"+":"."})."\n";
