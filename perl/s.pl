#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$ssl_ctx=SSL::CTX->new("SSLv3_client");

$ssl_ctx->set_options("-info_callback" =>
	sub	{
		print STDERR $_[0]->state()."\n";
		}
	);

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
$cbio=BIO->new("connect");
$cbio->hostname($conn) || die $ssl->error();

$bbio=BIO->new("buffer");

$sbio=BIO->new("ssl");
$ssl=$ssl_ctx->new_ssl;
$ssl->set_options(-connect_state);
$sbio->set_ssl($ssl);

$sbio->push($cbio);
$bbio->push($sbio);
$bio=$bbio;

#$bio->set_callback(
#	sub	{
#		my($bio,$state,$cmd,$buf,$lart,$ret)=@_;
#		print STDERR "$state:$cmd\n";
#		return($ret);
#		}
#	);

$b=$bio;
do	{
	print STDERR $b->type."\n";
	} while ($b=$b->next_bio);

(($ret=$bio->syswrite("GET / HTTP/1.0\r\n\r\n")) > 0) || die $bio->error();
$bio->flush;

$data="";
while (1)
	{
	$ret=$bio->getline;
	$ret =~ s/[\r\n]//g;
	print STDERR "$ret\n";
	last if $ret eq "";
	$server=$1 if $ret=~ /^Server: (.*)/;
	}


print "server is $server\n";
$x509=$ssl->get_peer_certificate();
print "version     :".$x509->get_version()."\n";
print "serialNumber:".$x509->get_serialNumber()->bn2hex."\n";
print "subject     :".$x509->get_subject_name()."\n";
print "issuer      :". $x509->get_issuer_name()."\n";

$c=$ssl->get_current_cipher;
($i,$a)=$c->get_bits;
$v=$c->get_version;
$n=$c->get_name;

print "protocol=".$ssl->get_version."\n";
print "bits=$i($a) cipher type=$v cipher=$n\n";

