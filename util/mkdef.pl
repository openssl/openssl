#!/usr/local/bin/perl
#
# generate a .def file
#
# It does this by parsing the header files and looking for the
# non-prototyped functions.
#

$crypto_num="util/libeay.num";
$ssl_num=   "util/ssleay.num";

$W32=1;
$NT=0;
foreach (@ARGV)
	{
	$W32=1 if $_ eq "32";
	$W32=0 if $_ eq "16";
	if($_ eq "NT") {
		$W32 = 1;
		$NT = 1;
	}
	$do_ssl=1 if $_ eq "ssleay";
	$do_ssl=1 if $_ eq "ssl";
	$do_crypto=1 if $_ eq "libeay";
	$do_crypto=1 if $_ eq "crypto";
	$do_update=1 if $_ eq "update";
	}

if (!$do_ssl && !$do_crypto)
	{
	print STDERR "usage: $0 ( ssl | crypto ) [ 16 | 32 ]\n";
	exit(1);
	}

%ssl_list=&load_numbers($ssl_num);
$max_ssl = $max_num;
%crypto_list=&load_numbers($crypto_num);
$max_crypto = $max_num;

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
$crypto.=" crypto/x509v3/x509v3.h";
$crypto.=" crypto/rand/rand.h";
$crypto.=" crypto/hmac/hmac.h";
$crypto.=" crypto/comp/comp.h";
$crypto.=" crypto/tmdiff.h";

$match{'NOPROTO'}=1;
$match2{'PERL5'}=1;

@ssl_func = &do_defs("SSLEAY", $ssl);
@crypto_func = &do_defs("LIBEAY", $crypto);

if ($do_update) {

if ($do_ssl == 1) {
	open(OUT, ">>$ssl_num");
	&update_numbers(*OUT,"SSLEAY",*ssl_list,$max_ssl, @ssl_func);
	close OUT;
}

if($do_crypto == 1) {
	open(OUT, ">>$crypto_num");
	&update_numbers(*OUT,"LIBEAY",*crypto_list,$max_crypto, @crypto_func);
	close OUT;
}

} else {

	&print_def_file(*STDOUT,"SSLEAY",*ssl_list,@ssl_func)
		if $do_ssl == 1;

	&print_def_file(*STDOUT,"LIBEAY",*crypto_list,@crypto_func)
		if $do_crypto == 1;

}


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
			last unless ($j >= 0);
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
#printf STDERR "$_\n%2d %2d %2d %2d %2d $W32\n",
#$tag{'NOPROTO'},$tag{'FreeBSD'},$tag{'WIN16'},$tag{'PERL5'},$tag{'NO_FP_API'};

			$t=undef;
			if (/^extern .*;$/)
				{ $t=&do_extern($name,$_); }
			elsif (	($tag{'NOPROTO'} == 1) &&
				($tag{'FreeBSD'} != 1) &&
				(($W32 && ($tag{'WIN16'} != 1)) ||
				 (!$W32 && ($tag{'WIN16'} != -1))) &&
				($tag{'PERL5'} != 1) &&
#				($tag{'_WINDLL'} != -1) &&
				((!$W32 && $tag{'_WINDLL'} != -1) ||
				 ($W32 && $tag{'_WINDLL'} != 1)) &&
				((($tag{'NO_FP_API'} != 1) && $W32) ||
				 (($tag{'NO_FP_API'} != -1) && !$W32)))
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
	elsif ((!$W32) && /(ERR_load_CRYPTO_strings)/)
		{ return("ERR_load_CRYPTOlib_strings"); }
	elsif (!$W32 && /BIO_s_file/)
		{ return(undef); }
	elsif (!$W32 && /BIO_new_file/)
		{ return(undef); }
	elsif (!$W32 && /BIO_new_fp/)
		{ return(undef); }
	elsif ($W32 && /BIO_s_file_internal/)
		{ return(undef); }
	elsif ($W32 && /BIO_new_file_internal/)
		{ return(undef); }
	elsif ($W32 && /BIO_new_fp_internal/)
		{ return(undef); }
        elsif (/SSL_add_dir_cert_subjects_to_stack/)
		{ return(undef); }
	elsif (!$NT && /BIO_s_log/)
		{ return(undef); }
	else
		{
		/\s\**(\S+)\s*\(/;
		$_ = $1;
		tr/()*//d;
#print STDERR "$1 : $_\n";
		return($_);
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

	if ($W32)
		{ $name.="32"; }
	else
		{ $name.="16"; }

	print OUT <<"EOF";
;
; Definition file for the DLL version of the $name library from OpenSSL
;

LIBRARY         $name

DESCRIPTION     'OpenSSL $name - http://www.openssl.org/'

EOF

	if (!$W32)
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
			printf STDERR "$func does not have a number assigned\n"
					if(!$do_update);
			}
		else
			{
			$n=$nums{$func};
			printf OUT "    %s%-40s@%d\n",($W32)?"":"_",$func,$n;
			}
		}
	printf OUT "\n";
	}

sub load_numbers
	{
	local($name)=@_;
	local($j,@a,%ret);

	$max_num = 0;

	open(IN,"<$name") || die "unable to open $name:$!\n";
	while (<IN>)
		{
		chop;
		s/#.*$//;
		next if /^\s*$/;
		@a=split;
		$ret{$a[0]}=$a[1];
		$max_num = $a[1] if $a[1] > $max_num;
		}
	close(IN);
	return(%ret);
	}

sub update_numbers
	{
	local(*OUT,$name,*nums,$start_num, @functions)=@_;
	my $new_funcs = 0;
	print STDERR "Updating $name\n";
	foreach $func (@functions)
		{
		if (!defined($nums{$func}))
			{
			$new_funcs++;
			printf OUT "%s%-40s%d\n","",$func, ++$start_num;
			}
		}
	if($new_funcs) {
		print STDERR "$new_funcs New Functions added\n";
	} else {
		print STDERR "No New Functions Added\n";
	}
	}
