#!/usr/local/bin/perl
#
# generate a .def file
#
# It does this by parsing the header files and looking for the
# non-prototyped functions.
#

$crypto_num="util/libeay.num";
$ssl_num=   "util/ssleay.num";

$NT=1;
foreach (@ARGV)
	{
	$NT=1 if $_ eq "32";
	$NT=0 if $_ eq "16";
	$do_ssl=1 if $_ eq "ssleay";
	$do_crypto=1 if $_ eq "libeay";
	}

if (!$do_ssl && !$do_crypto)
	{
	print STDERR "usage: $0 ( ssl | crypto ) [ 16 | 32 ]\n";
	exit(1);
	}

%ssl_list=&load_numbers($ssl_num);
%crypto_list=&load_numbers($crypto_num);

$ssl="ssl/ssl.h";

$crypto ="crypto/crypto.h";
$crypto.=" crypto/des/des.h";
$crypto.=" crypto/idea/idea.h";
$crypto.=" crypto/rc4/rc4.h";
$crypto.=" crypto/rc5/rc5.h";
$crypto.=" crypto/rc2/rc2.h";
$crypto.=" crypto/bf/blowfish.h";
$crypto.=" crypto/cast/cast.h";
$crypto.=" crypto/md2/md2.h";
$crypto.=" crypto/md5/md5.h";
$crypto.=" crypto/mdc2/mdc2.h";
$crypto.=" crypto/sha/sha.h";
$crypto.=" crypto/ripemd/ripemd.h";

$crypto.=" crypto/bn/bn.h";
$crypto.=" crypto/rsa/rsa.h";
$crypto.=" crypto/dsa/dsa.h";
$crypto.=" crypto/dh/dh.h";

$crypto.=" crypto/stack/stack.h";
$crypto.=" crypto/buffer/buffer.h";
$crypto.=" crypto/bio/bio.h";
$crypto.=" crypto/lhash/lhash.h";
$crypto.=" crypto/conf/conf.h";
$crypto.=" crypto/txt_db/txt_db.h";

$crypto.=" crypto/evp/evp.h";
$crypto.=" crypto/objects/objects.h";
$crypto.=" crypto/pem/pem.h";
#$crypto.=" crypto/meth/meth.h";
$crypto.=" crypto/asn1/asn1.h";
$crypto.=" crypto/asn1/asn1_mac.h";
$crypto.=" crypto/err/err.h";
$crypto.=" crypto/pkcs7/pkcs7.h";
$crypto.=" crypto/x509/x509.h";
$crypto.=" crypto/x509/x509_vfy.h";
$crypto.=" crypto/rand/rand.h";
$crypto.=" crypto/hmac/hmac.h";
$crypto.=" crypto/comp/comp.h";
$crypto.=" crypto/tmdiff.h";

$match{'NOPROTO'}=1;
$match2{'PERL5'}=1;

&print_def_file(*STDOUT,"SSLEAY",*ssl_list,&do_defs("SSLEAY",$ssl))
	if $do_ssl == 1;

&print_def_file(*STDOUT,"LIBEAY",*crypto_list,&do_defs("LIBEAY",$crypto))
	if $do_crypto == 1;

sub do_defs
	{
	local($name,$files)=@_;
	local(@ret);

	$off=-1;
	foreach $file (split(/\s+/,$files))
		{
#		print STDERR "reading $file\n";
		open(IN,"<$file") || die "unable to open $file:$!\n";
		$depth=0;
		$pr=-1;
		@np="";
		$/=undef;
		$a=<IN>;
		while (($i=index($a,"/*")) >= 0)
			{
			$j=index($a,"*/");
			break unless ($j >= 0);
			$a=substr($a,0,$i).substr($a,$j+2);
		#	print "$i $j\n";
			}
		foreach (split("\n",$a))
			{
			if (/^\#\s*ifndef (.*)/)
				{
				push(@tag,$1);
				$tag{$1}=-1;
				next;
				}
			elsif (/^\#\s*if !defined\(([^\)]+)\)/)
				{
				push(@tag,$1);
				$tag{$1}=-1;
				next;
				}
			elsif (/^\#\s*ifdef (.*)/)
				{
				push(@tag,$1);
				$tag{$1}=1;
				next;
				}
			elsif (/^\#\s*if defined(.*)/)
				{
				push(@tag,$1);
				$tag{$1}=1;
				next;
				}
			elsif (/^\#\s*endif/)
				{
				$tag{$tag[$#tag]}=0;
				pop(@tag);
				next;
				}
			elsif (/^\#\s*else/)
				{
				$t=$tag[$#tag];
				$tag{$t}= -$tag{$t};
				next;
				}
#printf STDERR "$_\n%2d %2d %2d %2d %2d $NT\n",
#$tag{'NOPROTO'},$tag{'FreeBSD'},$tag{'WIN16'},$tag{'PERL5'},$tag{'NO_FP_API'};

			$t=undef;
			if (/^extern .*;$/)
				{ $t=&do_extern($name,$_); }
			elsif (	($tag{'NOPROTO'} == 1) &&
				($tag{'FreeBSD'} != 1) &&
				(($NT && ($tag{'WIN16'} != 1)) ||
				 (!$NT && ($tag{'WIN16'} != -1))) &&
				($tag{'PERL5'} != 1) &&
#				($tag{'_WINDLL'} != -1) &&
				((!$NT && $tag{'_WINDLL'} != -1) ||
				 ($NT && $tag{'_WINDLL'} != 1)) &&
				((($tag{'NO_FP_API'} != 1) && $NT) ||
				 (($tag{'NO_FP_API'} != -1) && !$NT)))
				{ $t=&do_line($name,$_); }
			else
				{ $t=undef; }
			if (($t ne undef) && (!$done{$name,$t}))
				{
				$done{$name,$t}++;
				push(@ret,$t);
#printf STDERR "one:$t\n" if $t =~ /BIO_/;
				}
			}
		close(IN);
		}
	return(@ret);
	}

sub do_line
	{
	local($file,$_)=@_;
	local($n);

	return(undef) if /^$/;
	return(undef) if /^\s/;
#printf STDERR "two:$_\n" if $_ =~ /BIO_/;
	if (/(CRYPTO_get_locking_callback)/)
		{ return($1); }
	elsif (/(CRYPTO_get_id_callback)/)
		{ return($1); }
	elsif (/(CRYPTO_get_add_lock_callback)/)
		{ return($1); }
	elsif (/(SSL_CTX_get_verify_callback)/)
		{ return($1); }
	elsif (/(SSL_get_info_callback)/)
		{ return($1); }
	elsif ((!$NT) && /(ERR_load_CRYPTO_strings)/)
		{ return("ERR_load_CRYPTOlib_strings"); }
	elsif (!$NT && /BIO_s_file/)
		{ return(undef); }
	elsif (!$NT && /BIO_new_file/)
		{ return(undef); }
	elsif (!$NT && /BIO_new_fp/)
		{ return(undef); }
	elsif ($NT && /BIO_s_file_internal/)
		{ return(undef); }
	elsif ($NT && /BIO_new_file_internal/)
		{ return(undef); }
	elsif ($NT && /BIO_new_fp_internal/)
		{ return(undef); }
	else
		{
		/\s\**(\S+)\s*\(/;
		return($1);
		}
	}

sub do_extern
	{
	local($file,$_)=@_;
	local($n);

	/\s\**(\S+);$/;
	return($1);
	}

sub print_def_file
	{
	local(*OUT,$name,*nums,@functions)=@_;
	local($n)=1;

	if ($NT)
		{ $name.="32"; }
	else
		{ $name.="16"; }

	print OUT <<"EOF";
;
; Definition file for the DDL version of the $name library from SSLeay
;

LIBRARY         $name

DESCRIPTION     'SSLeay $name - eay\@cryptsoft.com'

EOF

	if (!$NT)
		{
		print <<"EOF";
CODE            PRELOAD MOVEABLE
DATA            PRELOAD MOVEABLE SINGLE

EXETYPE		WINDOWS

HEAPSIZE	4096
STACKSIZE	8192

EOF
		}

	print "EXPORTS\n";


	(@e)=grep(/^SSLeay/,@functions);
	(@r)=grep(!/^SSLeay/,@functions);
	@functions=((sort @e),(sort @r));

	foreach $func (@functions)
		{
		if (!defined($nums{$func}))
			{
			printf STDERR "$func does not have a number assigned\n";
			}
		else
			{
			$n=$nums{$func};
			printf OUT "    %s%-35s@%d\n",($NT)?"":"_",$func,$n;
			}
		}
	printf OUT "\n";
	}

sub load_numbers
	{
	local($name)=@_;
	local($j,@a,%ret);

	open(IN,"<$name") || die "unable to open $name:$!\n";
	while (<IN>)
		{
		chop;
		s/#.*$//;
		next if /^\s*$/;
		@a=split;
		$ret{$a[0]}=$a[1];
		}
	close(IN);
	return(%ret);
	}
