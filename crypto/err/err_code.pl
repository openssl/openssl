#!/usr/local/bin/perl

%errfile=(
	"ERR",	"NONE",
	"BN",	"bn/bn.err",
	"RSA",	"rsa/rsa.err",
	"DSA",	"dsa/dsa.err",
	"DH",	"dh/dh.err",
	"EVP",	"evp/evp.err",
	"BUF",	"buffer/buffer.err",
	"BIO",	"bio/bio.err",
	"OBJ",	"objects/objects.err",
	"PEM",	"pem/pem.err",
	"X509",	"x509/x509.err",
	"METH",	"meth/meth.err",
	"ASN1",	"asn1/asn1.err",
	"CONF",	"conf/conf.err",
	"PROXY","proxy/proxy.err",
	"PKCS7","pkcs7/pkcs7.err",
	"RSAREF","../rsaref/rsaref.err",
	"SSL",	"../ssl/ssl.err",
	"SSL2",	"../ssl/ssl2.err",
	"SSL3",	"../ssl/ssl3.err",
	"SSL23","../ssl/ssl23.err",
	);

$function{'RSAREF_F_RSA_BN2BIN'}=1;
$function{'RSAREF_F_RSA_PRIVATE_DECRYPT'}=1;
$function{'RSAREF_F_RSA_PRIVATE_ENCRYPT'}=1;
$function{'RSAREF_F_RSA_PUBLIC_DECRYPT'}=1;
$function{'RSAREF_F_RSA_PUBLIC_ENCRYPT'}=1;
$function{'SSL_F_CLIENT_CERTIFICATE'}=1;

$r_value{'SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE'}=	1010;
$r_value{'SSL_R_SSLV3_ALERT_BAD_RECORD_MAC'}=	1020;
$r_value{'SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE'}=1030;
$r_value{'SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE'}=	1040;
$r_value{'SSL_R_SSLV3_ALERT_NO_CERTIFICATE'}=	1041;
$r_value{'SSL_R_SSLV3_ALERT_BAD_CERTIFICATE'}=	1042;
$r_value{'SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE'}=1043;
$r_value{'SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED'}=	1044;
$r_value{'SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED'}=	1045;
$r_value{'SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN'}=	1046;
$r_value{'SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER'}=	1047;

$r_value{'RSAREF_R_CONTENT_ENCODING'}=	0x0400;
$r_value{'RSAREF_R_DATA'}=		0x0401;
$r_value{'RSAREF_R_DIGEST_ALGORITHM'}=	0x0402;
$r_value{'RSAREF_R_ENCODING'}=		0x0403;
$r_value{'RSAREF_R_KEY'}=		0x0404;
$r_value{'RSAREF_R_KEY_ENCODING'}=	0x0405;
$r_value{'RSAREF_R_LEN'}=		0x0406;
$r_value{'RSAREF_R_MODULUS_LEN'}=	0x0407;
$r_value{'RSAREF_R_NEED_RANDOM'}=	0x0408;
$r_value{'RSAREF_R_PRIVATE_KEY'}=	0x0409;
$r_value{'RSAREF_R_PUBLIC_KEY'}=	0x040a;
$r_value{'RSAREF_R_SIGNATURE'}=		0x040b;
$r_value{'RSAREF_R_SIGNATURE_ENCODING'}=0x040c;
$r_value{'RSAREF_R_ENCRYPTION_ALGORITHM'}=0x040d;

$last="";
while (<>)
	{
	if (/err\(([A-Z0-9]+_F_[0-9A-Z_]+)\s*,\s*([0-9A-Z]+_R_[0-9A-Z_]+)\s*\)/)
		{
		if ($1 != $last)
			{
			if ($function{$1} == 0)
				{
				printf STDERR "$. $1 is bad\n";
				}
			}
		$function{$1}++;
		$last=$1;
		$reason{$2}++;
		}
	}

foreach (keys %function,keys %reason)
	{
	/^([A-Z0-9]+)_/;
	$prefix{$1}++;
	}

@F=sort keys %function;
@R=sort keys %reason;
foreach $j (sort keys %prefix)
	{
	next if $errfile{$j} eq "NONE";
	printf STDERR "doing %-6s - ",$j;
	open(OUT,">$errfile{$j}") || die "unable to open '$errfile{$j}':$!\n";
	@f=grep(/^${j}_/,@F);
	@r=grep(/^${j}_/,@R);
	$num=100;
	print OUT "/* Error codes for the $j functions. */\n\n";
	print OUT "/* Function codes. */\n";
	$f_count=0;
	foreach $i (@f)
		{
		$z=6-int(length($i)/8);
		printf OUT "#define $i%s $num\n","\t" x $z;
		$num++;
		$f_count++;
		}
	$num=100;
	print OUT "\n/* Reason codes. */\n";
	$r_count=0;
	foreach $i (@r)
		{
		$z=6-int(length($i)/8);
		if (defined($r_value{$i}))
			{
			printf OUT "#define $i%s $r_value{$i}\n","\t" x $z;
			}
		else
			{
			printf OUT "#define $i%s $num\n","\t" x $z;
			$num++;
			}
		$r_count++;
		}
	close(OUT);

	printf STDERR "%3d functions, %3d reasons\n",$f_count,$r_count;
	}

