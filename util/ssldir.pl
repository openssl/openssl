#!/usr/local/bin/perl

$#ARGV == 0 || die "usage: ssldir.pl /new/path\n";
@files=('crypto/cryptlib.h',
	'Makefile.ssl',
	'tools/c_rehash',
	'util/mk1mf.pl',
	);

%cryptlib=(
	'\sX509_CERT_AREA\s',"#define X509_CERT_AREA\t\t".'"%s"',
	'\sX509_CERT_DIR\s', "#define X509_CERT_DIR\t\t".'"%s/certs"',
	'\sX509_CERT_FILE\s', "#define X509_CERT_FILE\t\t".'"%s/cert.pem"',
	'\sX509_PRIVATE_DIR\s',"#define X509_PRIVATE_DIR\t".'"%s/private"',
	);

%Makefile_ssl=(
	'^INSTALLTOP=','INSTALLTOP=%s',
	);

%c_rehash=(
	'^DIR=',	'DIR=%s',
	);

%mk1mf=(
	'^\$INSTALLTOP=','$INSTALLTOP="%s";',
	);

&dofile("crypto/cryptlib.h",$ARGV[0],%cryptlib);
&dofile("Makefile.ssl",$ARGV[0],%Makefile_ssl);
&dofile("tools/c_rehash",$ARGV[0],%c_rehash);
&dofile("util/mk1mf.pl",$ARGV[0],%mk1mf);

sub dofile
	{
	($f,$p,%m)=@_;

	open(IN,"<$f") || die "unable to open $f:$!\n";
	@a=<IN>;
	close(IN);
	foreach $k (keys %m)
		{
		grep(/$k/ && ($_=sprintf($m{$k}."\n",$p)),@a);
		}
	($ff=$f) =~ s/\..*$//;
	open(OUT,">$ff.new") || die "unable to open $f:$!\n";
	print OUT @a;
	close(OUT);
	rename($f,"$ff.bak") || die "unable to rename $f\n";
	rename("$ff.new",$f) || die "unable to rename $ff.new\n";
	}

