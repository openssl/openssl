#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$ssl_ctx=SSL::CTX->new("SSLv3");

$ssl_ctx->set_options("-info_callback" =>
	sub	{
		print STDERR $_[0]->state()."\n";
		}
	);

$ssl_ctx->use_PrivateKey_file("server.pem");

$conn="localhost:4433";
$conn=$ARGV[0] if $#ARGV >= 0;
$bio=BIO->new("connect");
$bio->hostname($conn) || die $ssl->error();

$ssl=$ssl_ctx->new_ssl;
$ssl->set_bio($bio);

(($ret=$ssl->connect()) > 0) || die $ssl->error();

(($ret=$ssl->write("GET / HTTP/1.0\r\n\r\n")) > 0) || die $ssl->error();

while (1)
	{
	$ret=$ssl->read($buf,10240);
	last if ($ret <= 0);
	print $buf;
	}

