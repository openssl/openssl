#!/usr/my/bin/perl -w
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
	$rsaref=1 if $_ eq "rsaref";
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
$crypto.=" crypto/pkcs12/pkcs12.h";
$crypto.=" crypto/x509/x509.h";
$crypto.=" crypto/x509/x509_vfy.h";
$crypto.=" crypto/x509v3/x509v3.h";
$crypto.=" crypto/rand/rand.h";
$crypto.=" crypto/hmac/hmac.h";
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
	my $err = 0;
	$err += &print_def_file(*STDOUT,"SSLEAY",*ssl_list,@ssl_func)
		if $do_ssl == 1;

	$err += &print_def_file(*STDOUT,"LIBEAY",*crypto_list,@crypto_func)
		if $do_crypto == 1;
	exit($err);
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
				$funcs{"sk_${1}_pop"} = 1;
				$funcs{"sk_${1}_find"} = 1;
				$funcs{"sk_${1}_delete"} = 1;
				$funcs{"sk_${1}_delete_ptr"} = 1;
				$funcs{"sk_${1}_set_cmp_func"} = 1;
				$funcs{"sk_${1}_dup"} = 1;
				$funcs{"sk_${1}_pop_free"} = 1;
				$funcs{"sk_${1}_shift"} = 1;
			} elsif ($safe_stack_def &&
				/^\s*DECLARE_ASN1_SET_OF\s*\(\s*(\w*)\s*\)/) {
				$funcs{"d2i_ASN1_SET_OF_${1}"} = 1;
				$funcs{"i2d_ASN1_SET_OF_${1}"} = 1;
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
	my $nodef=0;

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
		    if(!$do_update) {
			printf STDERR "$func does not have a number assigned\n";
			$nodef = 1;
		    }
		} else {
			$n=$nums{$func};
			printf OUT "    %s%-40s@%d\n",($W32)?"":"_",$func,$n;
		}
	}
	printf OUT "\n";
	return ($nodef);
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
