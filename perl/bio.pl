#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$cmd=<<"EOF";
GET / HTTP/1.0

EOF

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
$bio=SSLeay::BIO::new("connect");
#$bio->set_callback(sub {print STDERR SSLeay::BIO::number_read($_[0])."\n"; $_[$#_] });
#$bio->set_callback(sub {print STDERR "$#_:".$_[0].":$_[1]:$_[2]:$_[3]:$_[4]:\n"; $_[$#_] });
$bio->hostname($conn) || die $ssl->error();


(($ret=$bio->do_handshake()) > 0) || die $bio->error();

(($ret=$bio->syswrite($cmd)) > 0) || die $bio->error();

while (1)
	{
	$ret=$bio->sysread($buf,10240);
	last if ($ret <= 0);
	print $buf;
	}

