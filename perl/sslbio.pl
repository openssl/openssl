#!/usr/local/bin/perl

use ExtUtils::testlib;

use SSLeay;

$ssl_ctx=SSL::CTX->new("SSLv3");

#$ssl_ctx->set_options("-info_callback" =>
#	sub	{
#		print STDOUT $_[0]->state()."\n";
#		}
#	);

# create a ssl bio
$bssl=BIO->new("ssl");
$bssl->set_ssl($ssl_ctx->new_ssl()) || die $bssl->error();
$bssl->get_ssl->set_options("-connect_state") || die $ssl->error();

$bssl->set_callback(sub { printf "XXXXXXXXXXXXXXXXXXXXXX %d %s\n",$_[1],$_[0]->type; });

# create connect bio
$host="localhost:4433";
$host=$ARGV[0] if $#ARGV >= 0;
$bio=BIO->new("connect");
$bio->hostname($host) || die $bio->error();

# push it in
$bssl->push($bio);

(($ret=$bssl->write("GET / HTTP/1.0\r\n\r\n")) > 0) || die $bssl->error();

while (1)
	{
	$ret=$bssl->read($buf,10240);
	last if ($ret <= 0);
	print $buf;
	}


