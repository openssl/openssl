#!/usr/local/bin/perl
#
# Up the version numbers in the files.
#

@files=(
	"crypto/crypto.h",
	"crypto/des/ecb_enc.c",
	"crypto/idea/i_ecb.c",
	"crypto/lhash/lhash.c",
	"crypto/conf/conf.c",
	"crypto/md2/md2_dgst.c",
	"crypto/md5/md5_dgst.c",
	"crypto/ripemd/rmd_dgst.c",
	"crypto/pem/pem_lib.c",
	"crypto/bn/bn_lib.c",
	"crypto/dh/dh_lib.c",
	"crypto/rc2/rc2_ecb.c",
	"crypto/rc4/rc4_skey.c",
	"crypto/rc5/rc5_ecb.c",
	"crypto/bf/bf_ecb.c",
	"crypto/cast/c_ecb.c",
	"crypto/rsa/rsa_lib.c",
	"crypto/dsa/dsa_lib.c",
	"crypto/sha/sha1dgst.c",
	"crypto/sha/sha_dgst.c",
	"crypto/asn1/asn1_lib.c",
	"crypto/x509/x509_vfy.c",
	"crypto/evp/evp_enc.c",
	"crypto/rand/md_rand.c",
	"crypto/stack/stack.c",
	"crypto/txt_db/txt_db.c",
	"crypto/cversion.c",
	"ssl/ssl_lib.c",
	"ssl/s2_lib.c",
	"ssl/s3_lib.c",
	"ssl/s23_lib.c",
	"ssl/t1_lib.c",
	"README",
	);

@month=('Jan','Feb','Mar','Apr','May','Jun',
	'Jul','Aug','Sep','Oct','Nov','Dec');
@a=localtime(time());
$time=sprintf("%02d-%s-%04d",$a[3],$month[$a[4]],$a[5]+1900);

$ver=$ARGV[0];
($ver ne "") || die "no version number specified\n";
($a,$b,$c,$d)=unpack('axaxac',$ver);
$d=defined($d)?$d-96:0;
$xver=sprintf("%x%x%x%x",$a,$b,$c,$d);

foreach $file (@files)
	{
	open(IN,"<$file") || die "unable to open $file:$!\n";
	open(OUT,">$file.new") || die "unable to open $file.new:$!\n";
	$found=0;

	print STDERR "$file:";

	while (<IN>)
		{
		if ((s/(SSLeay|OpenSSL|SSLeay\/OpenSSL) \d\.\d.\d[^"]*(\"|\s)/OpenSSL $ver $time\2/) ||
			s/^(\#define\s+OPENSSL_VERSION_NUMBER\s+0x)[0-9a-zA-Z]+(.*)$/$1$xver$2/)
			{
			print STDERR " Done";
			$found++;
			print OUT;
			while (<IN>) { print OUT; }
			last;
			}
		print OUT;
		}
	print STDERR "\n";
	close(IN);
	close(OUT);
	(!$found) && die "unable to update the version number in $file\n";
	rename($file,"$file.bak") || die "unable to rename $file:$!\n";
	rename("$file.new",$file) || die "unable to rename $file.new:$!\n";
	}
