#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$ssl_ctx=SSL::CTX->new("SSLv3");

#$ssl_ctx->set_options("-info_callback" =>
#	sub	{
#		print STDERR $_[0]->state()."\n";
#		}
#	);

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
$bio=BIO->new("connect");
$bio->hostname($conn) || die $ssl->error();

#$bbio=BIO->new("buffer");
#$bbio->push($cbio);
#$bio=$bbio;

#$bio->set_callback(
#	sub	{
#		my($bio,$state,$cmd,$buf,$lart,$ret)=@_;
#		print STDERR "$state:$cmd\n";
#		return($ret);
#		}
#	);

print STDERR "-1 ABCD\n";
$ssl=$ssl_ctx->new_ssl;
print STDERR "000 ABCD\n";
$ssl->set_bio($bio);

print STDERR "00 ABCD\n";
(($ret=$ssl->connect()) > 0) || die $ssl->error();

print STDERR "0 ABCD\n";

(($ret=$ssl->syswrite("GET / HTTP/1.0\r\n\r\n")) > 0) || die $ssl->error();

print STDERR "1 ABCD\n";
$data="";
while (1)
	{
print STDERR "2 ABCD\n";
	$ret=$ssl->sysread($buf,1024);
print STDERR "3 ABCD\n";
	last if $ret <= 0;
	$data.=$buf;
	}

print STDERR "4 ABCD\n";
@a=split(/[\r]\n/,$data);
($server)=grep(/^Server:/,@a);

print "$server\n";
$x509=$ssl->get_peer_certificate();
print "subject:".$x509->get_subject_name()."\n";
print "issuer:". $x509->get_issuer_name()."\n";

$c=$ssl->get_current_cipher;
($i,$a)=$c->get_bits;
$v=$c->get_version;
$n=$c->get_name;

print "protocol=".$ssl->get_version."\n";
print "bits=$i($a) cipher type=$v cipher=$n\n";

