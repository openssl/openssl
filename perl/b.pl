#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$cmd=<<"EOF";

EOF

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
print "X\n";
$bio=BIO->new("connect");
print "XX\n";
$bio->set_callback(sub {print STDERR $_[0]->number_read."\n"; $_[$#_] });
print "XXX\n";
$bio->hostname($conn) || die $ssl->error();
print "XXXX\n";

#$ssl=BIO->new("ssl");
