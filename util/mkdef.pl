#!/usr/local/bin/perl -w
#
# generate a .def file
#
# It does this by parsing the header files and looking for the
# prototyped functions: it then prunes the output.
#

$crypto_num="util/libeay.num";
$ssl_num=   "util/ssleay.num";

my $do_update = 0;
my $do_crypto = 0;
my $do_ssl = 0;
$rsaref = 0;

$W32=1;
$NT=0;
# Set this to make typesafe STACK definitions appear in DEF
$safe_stack_def = 1;

$options="";
open(IN,"<Makefile.ssl") || die "unable to open Makefile.ssl!\n";
while(<IN>) {
    $options=$1 if (/^OPTIONS=(.*)$/);
}
close(IN);

foreach (@ARGV, split(/ /, $options))
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
	$rsaref=1 if $_ eq "rsaref";

	if    (/^no-rc2$/)      { $no_rc2=1; }
	elsif (/^no-rc4$/)      { $no_rc4=1; }
	elsif (/^no-rc5$/)      { $no_rc5=1; }
	elsif (/^no-idea$/)     { $no_idea=1; }
	elsif (/^no-des$/)      { $no_des=1; }
	elsif (/^no-bf$/)       { $no_bf=1; }
	elsif (/^no-cast$/)     { $no_cast=1; }
	elsif (/^no-md2$/)      { $no_md2=1; }
	elsif (/^no-md5$/)      { $no_md5=1; }
	elsif (/^no-sha$/)      { $no_sha=1; }
	elsif (/^no-ripemd$/)   { $no_ripemd=1; }
	elsif (/^no-mdc2$/)     { $no_mdc2=1; }
	elsif (/^no-rsa$/)      { $no_rsa=1; }
	elsif (/^no-dsa$/)      { $no_dsa=1; }
	elsif (/^no-dh$/)       { $no_dh=1; }
	elsif (/^no-hmac$/)	{ $no_hmac=1; }
	}

if (!$do_ssl && !$do_crypto)
	{
	print STDERR "usage: $0 ( ssl | crypto ) [ 16 | 32 | NT ] [rsaref]\n";
	exit(1);
	}

%ssl_list=&load_numbers($ssl_num);
$max_ssl = $max_num;
%crypto_list=&load_numbers($crypto_num);
$max_crypto = $max_num;

$ssl="ssl/ssl.h";

$crypto ="crypto/crypto.h";
$crypto.=" crypto/des/des.h" unless $no_des;
$crypto.=" crypto/idea/idea.h" unless $no_idea;
$crypto.=" crypto/rc4/rc4.h" unless $no_rc4;
$crypto.=" crypto/rc5/rc5.h" unless $no_rc5;
$crypto.=" crypto/rc2/rc2.h" unless $no_rc2;
$crypto.=" crypto/bf/blowfish.h" unless $no_bf;
$crypto.=" crypto/cast/cast.h" unless $no_cast;
$crypto.=" crypto/md2/md2.h" unless $no_md2;
$crypto.=" crypto/md5/md5.h" unless $no_md5;
$crypto.=" crypto/mdc2/mdc2.h" unless $no_mdc2;
$crypto.=" crypto/sha/sha.h" unless $no_sha;
$crypto.=" crypto/ripemd/ripemd.h" unless $no_ripemd;

$crypto.=" crypto/bn/bn.h";
$crypto.=" crypto/rsa/rsa.h" unless $no_rsa;
$crypto.=" crypto/dsa/dsa.h" unless $no_dsa;
$crypto.=" crypto/dh/dh.h" unless $no_dh;
$crypto.=" crypto/hmac/hmac.h" unless $no_hmac;

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
$crypto.=" crypto/pkcs12/pkcs12.h";
$crypto.=" crypto/x509/x509.h";
$crypto.=" crypto/x509/x509_vfy.h";
$crypto.=" crypto/x509v3/x509v3.h";
$crypto.=" crypto/rand/rand.h";
$crypto.=" crypto/comp/comp.h";
$crypto.=" crypto/tmdiff.h";

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
	my($name,$files)=@_;
	my @ret;
	my %funcs;

	foreach $file (split(/\s+/,$files))
		{
		open(IN,"<$file") || die "unable to open $file:$!\n";

		my $line = "", $def= "";
		my %tag = (
			FreeBSD		=> 0,
			NOPROTO		=> 0,
			WIN16		=> 0,
			PERL5		=> 0,
			_WINDLL		=> 0,
			NO_FP_API	=> 0,
			CONST_STRICT	=> 0,
			TRUE		=> 1,
		);
		while(<IN>) {
			last if (/BEGIN ERROR CODES/);
			if ($line ne '') {
				$_ = $line . $_;
				$line = '';
			}

			if (/\\$/) {
				$line = $_;
				next;
			}

	    		$cpp = 1 if /^#.*ifdef.*cplusplus/;
			if ($cpp) {
				$cpp = 0 if /^#.*endif/;
				next;
	    		}

			s/\/\*.*?\*\///gs;                   # ignore comments
			s/{[^{}]*}//gs;                      # ignore {} blocks
			if (/^\#\s*ifndef (.*)/) {
				push(@tag,$1);
				$tag{$1}=-1;
				next;
			} elsif (/^\#\s*if !defined\(([^\)]+)\)/) {
				push(@tag,$1);
				$tag{$1}=-1;
				next;
			} elsif (/^\#\s*ifdef (.*)/) {
				push(@tag,$1);
				$tag{$1}=1;
				next;
			} elsif (/^\#\s*if defined(.*)/) {
				push(@tag,$1);
				$tag{$1}=1;
				next;
			} elsif (/^\#\s*endif/) {
				$tag{$tag[$#tag]}=0;
				pop(@tag);
				next;
			} elsif (/^\#\s*else/) {
				my $t=$tag[$#tag];
				$tag{$t}= -$tag{$t};
				next;
			} elsif (/^\#\s*if\s+1/) {
				# Dummy tag
				push(@tag,"TRUE");
				$tag{"TRUE"}=1;
				next;
			} elsif (/^\#/) {
				next;
			}
			if ($safe_stack_def &&
				/^\s*DECLARE_STACK_OF\s*\(\s*(\w*)\s*\)/) {
				$funcs{"sk_${1}_new"} = 1;
				$funcs{"sk_${1}_new_null"} = 1;
				$funcs{"sk_${1}_free"} = 1;
				$funcs{"sk_${1}_num"} = 1;
				$funcs{"sk_${1}_value"} = 1;
				$funcs{"sk_${1}_set"} = 1;
				$funcs{"sk_${1}_zero"} = 1;
				$funcs{"sk_${1}_push"} = 1;
				$funcs{"sk_${1}_unshift"} = 1;
				$funcs{"sk_${1}_find"} = 1;
				$funcs{"sk_${1}_delete"} = 1;
				$funcs{"sk_${1}_delete_ptr"} = 1;
				$funcs{"sk_${1}_insert"} = 1;
				$funcs{"sk_${1}_set_cmp_func"} = 1;
				$funcs{"sk_${1}_dup"} = 1;
				$funcs{"sk_${1}_pop_free"} = 1;
				$funcs{"sk_${1}_shift"} = 1;
				$funcs{"sk_${1}_pop"} = 1;
				$funcs{"sk_${1}_sort"} = 1;
			} elsif ($safe_stack_def &&
				/^\s*DECLARE_ASN1_SET_OF\s*\(\s*(\w*)\s*\)/) {
				$funcs{"d2i_ASN1_SET_OF_${1}"} = 1;
				$funcs{"i2d_ASN1_SET_OF_${1}"} = 1;
			} elsif (/^DECLARE_PEM_rw\s*\(\s*(\w*)\s*,/ ||
				     /^DECLARE_PEM_rw_cb\s*\(\s*(\w*)\s*,/ ) {
				if($W32) {
					$funcs{"PEM_read_${1}"} = 1;
					$funcs{"PEM_write_${1}"} = 1;
				}
				$funcs{"PEM_read_bio_${1}"} = 1;
				$funcs{"PEM_write_bio_${1}"} = 1;
			} elsif ( 
				($tag{'FreeBSD'} != 1) &&
				($tag{'CONST_STRICT'} != 1) &&
				(($W32 && ($tag{'WIN16'} != 1)) ||
				 (!$W32 && ($tag{'WIN16'} != -1))) &&
				($tag{'PERL5'} != 1) &&
#				($tag{'_WINDLL'} != -1) &&
				((!$W32 && $tag{'_WINDLL'} != -1) ||
				 ($W32 && $tag{'_WINDLL'} != 1)) &&
				((($tag{'NO_FP_API'} != 1) && $W32) ||
				 (($tag{'NO_FP_API'} != -1) && !$W32)))
				{
					if (/{|\/\*/) { # }
						$line = $_;
					} else {
						$def .= $_;
					}
				}
			}
		close(IN);

		foreach (split /;/, $def) {
			s/^[\n\s]*//g;
			s/[\n\s]*$//g;
			next if(/typedef\W/);
			next if(/EVP_bf/ and $no_bf);
			next if(/EVP_cast/ and $no_cast);
			next if(/EVP_des/ and $no_des);
			next if(/EVP_dss/ and $no_dsa);
			next if(/EVP_idea/ and $no_idea);
			next if(/EVP_md2/ and $no_md2);
			next if(/EVP_md5/ and $no_md5);
			next if(/EVP_rc2/ and $no_rc2);
			next if(/EVP_rc4/ and $no_rc4);
			next if(/EVP_rc5/ and $no_rc5);
			next if(/EVP_ripemd/ and $no_ripemd);
			next if(/EVP_sha/ and $no_sha);
			if (/\(\*(\w*)\([^\)]+/) {
				$funcs{$1} = 1;
			} elsif (/\w+\W+(\w+)\W*\(\s*\)$/s) {
				# K&R C
				next;
			} elsif (/\w+\W+\w+\W*\(.*\)$/s) {
				while (not /\(\)$/s) {
					s/[^\(\)]*\)$/\)/s;
					s/\([^\(\)]*\)\)$/\)/s;
				}
				s/\(void\)//;
				/(\w+)\W*\(\)/s;
				$funcs{$1} = 1;
			} elsif (/\(/ and not (/=/)) {
				print STDERR "File $file: cannot parse: $_;\n";
			}
		}
	}

	# Prune the returned functions

        delete $funcs{"SSL_add_dir_cert_subjects_to_stack"};
        delete $funcs{"des_crypt"};
        delete $funcs{"RSA_PKCS1_RSAref"} unless $rsaref;

	if($W32) {
		delete $funcs{"BIO_s_file_internal"};
		delete $funcs{"BIO_new_file_internal"};
		delete $funcs{"BIO_new_fp_internal"};
	} else {
		if(exists $funcs{"ERR_load_CRYPTO_strings"}) {
			delete $funcs{"ERR_load_CRYPTO_strings"};
			$funcs{"ERR_load_CRYPTOlib_strings"} = 1;
		}
		delete $funcs{"BIO_s_file"};
		delete $funcs{"BIO_new_file"};
		delete $funcs{"BIO_new_fp"};
	}
	if (!$NT) {
		delete $funcs{"BIO_s_log"};
	}

	push @ret, keys %funcs;

	return(@ret);
}

sub print_def_file
{
	(*OUT,my $name,*nums,@functions)=@_;
	my $n =1;

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

	if (!$W32) {
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

	foreach $func (@functions) {
		if (!defined($nums{$func})) {
			printf STDERR "$func does not have a number assigned\n"
					if(!$do_update);
		} else {
			$n=$nums{$func};
			printf OUT "    %s%-40s@%d\n",($W32)?"":"_",$func,$n;
		}
	}
	printf OUT "\n";
}

sub load_numbers
{
	my($name)=@_;
	my(@a,%ret);

	$max_num = 0;

	open(IN,"<$name") || die "unable to open $name:$!\n";
	while (<IN>) {
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
	(*OUT,$name,*nums,my $start_num, my @functions)=@_;
	my $new_funcs = 0;
	print STDERR "Updating $name\n";
	foreach $func (@functions) {
		if (!exists $nums{$func}) {
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
