#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$ssl_ctx=SSL::CTX->new("SSLv3");

$ssl_ctx->set_options("-info_callback" =>
	sub	{
		print STDERR $_[0]->state()."\n";
		}
	);

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
$cbio=BIO->new("connect");
$cbio->hostname($conn) || die $ssl->error();

$ssl=$ssl_ctx->new_ssl;
$sbio=BIO->new("ssl");
$sbio->set_ssl($ssl);
$ssl->set_options("-connect_state");

$bio=BIO->new("buffer");

$sbio->push($cbio);
$bio->push($sbio);

($bio->do_handshake() > 0) || die $bio->error();

(($ret=$bio->syswrite("GET / HTTP/1.0\r\n\r\n")) > 0) || die $ssl->error();
$bio->flush() || die $bio->error();

$data="";
while ($_=$bio->getline())
	{
	if (/^Server:/)
		{
		print;
		last;
		}
	}

if ($bio->peek_error())
	{
	print "There was an error:".$ssl->error();
	}
print "exit\n";
