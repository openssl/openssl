#!/usr/local/bin/perl -w
#
# generate a .def file
#
# It does this by parsing the header files and looking for the
# prototyped functions: it then prunes the output.
#
# Intermediary files are created, call libeay.num and ssleay.num,...
# Previously, they had the following format:
#
#	routine-name	nnnn
#
# But that isn't enough for a number of reasons, the first on being that
# this format is (needlessly) very Win32-centric, and even then...
# One of the biggest problems is that there's no information about what
# routines should actually be used, which varies with what crypto algorithms
# are disabled.  Also, some operating systems (for example VMS with VAX C)
# need to keep track of the global variables as well as the functions.
#
# So, a remake of this script is done so as to include information on the
# kind of symbol it is (function or variable) and what algorithms they're
# part of.  This will allow easy translating to .def files or the corresponding
# file in other operating systems (a .opt file for VMS, possibly with a .mar
# file).
#
# The format now becomes:
#
#	routine-name	nnnn	info
#
# and the "info" part is actually a colon-separated string of fields with
# the following meaning:
#
#	existence:platform:kind:algorithms
#
# - "existence" can be "EXIST" or "NOEXIST" depending on if the symbol is
#   found somewhere in the source, 
# - "platforms" is empty if it exists on all platforms, otherwise it contains
#   comma-separated list of the platform, just as they are if the symbol exists
#   for those platforms, or prepended with a "!" if not.  This helps resolve
#   symbol name replacements for platforms where the names are too long for the
#   compiler or linker, or if the systems is case insensitive and there is a
#   clash.  This script assumes those redefinitions are place in the file
#   crypto/symhacks.h.
#   The semantics for the platforms list is a bit complicated.  The rule of
#   thumb is that the list is exclusive, but it seems to mean different things.
#   So, if the list is all negatives (like "!VMS,!WIN16"), the symbol exists
#   on all platforms except those listed.  If the list is all positives (like
#   "VMS,WIN16"), the symbol exists only on those platforms and nowhere else.
#   The combination of positives and negatives will act as if the positives
#   weren't there.
# - "kind" is "FUNCTION" or "VARIABLE".  The meaning of that is obvious.
# - "algorithms" is a comma-separated list of algorithm names.  This helps
#   exclude symbols that are part of an algorithm that some user wants to
#   exclude.
#

my $crypto_num= "util/libeay.num";
my $ssl_num=    "util/ssleay.num";

my $do_update = 0;
my $do_rewrite = 0;
my $do_crypto = 0;
my $do_ssl = 0;
my $do_ctest = 0;
my $do_ctestall = 0;
my $rsaref = 0;

my $VMS=0;
my $W32=0;
my $W16=0;
my $NT=0;
# Set this to make typesafe STACK definitions appear in DEF
my $safe_stack_def = 0;

my @known_platforms = ( "__FreeBSD__", "VMS", "WIN16", "WIN32",
			"WINNT", "PERL5", "NeXT" );
my @known_algorithms = ( "RC2", "RC4", "RC5", "IDEA", "DES", "BF",
			 "CAST", "MD2", "MD4", "MD5", "SHA", "RIPEMD",
			 "MDC2", "RSA", "DSA", "DH", "HMAC", "FP_API" );

my $options="";
open(IN,"<Makefile.ssl") || die "unable to open Makefile.ssl!\n";
while(<IN>) {
    $options=$1 if (/^OPTIONS=(.*)$/);
}
close(IN);

# The following ciphers may be excluded (by Configure). This means functions
# defined with ifndef(NO_XXX) are not included in the .def file, and everything
# in directory xxx is ignored.
my $no_rc2; my $no_rc4; my $no_rc5; my $no_idea; my $no_des; my $no_bf;
my $no_cast;
my $no_md2; my $no_md4; my $no_md5; my $no_sha; my $no_ripemd; my $no_mdc2;
my $no_rsa; my $no_dsa; my $no_dh; my $no_hmac=0;
my $no_fp_api;

foreach (@ARGV, split(/ /, $options))
	{
	$W32=1 if $_ eq "32";
	$W16=1 if $_ eq "16";
	if($_ eq "NT") {
		$W32 = 1;
		$NT = 1;
	}
	$VMS=1 if $_ eq "VMS";
	$rsaref=1 if $_ eq "rsaref";

	$do_ssl=1 if $_ eq "ssleay";
	$do_ssl=1 if $_ eq "ssl";
	$do_crypto=1 if $_ eq "libeay";
	$do_crypto=1 if $_ eq "crypto";
	$do_update=1 if $_ eq "update";
	$do_rewrite=1 if $_ eq "rewrite";
	$do_ctest=1 if $_ eq "ctest";
	$do_ctestall=1 if $_ eq "ctestall";
	#$safe_stack_def=1 if $_ eq "-DDEBUG_SAFESTACK";

	if    (/^no-rc2$/)      { $no_rc2=1; }
	elsif (/^no-rc4$/)      { $no_rc4=1; }
	elsif (/^no-rc5$/)      { $no_rc5=1; }
	elsif (/^no-idea$/)     { $no_idea=1; }
	elsif (/^no-des$/)      { $no_des=1; $no_mdc2=1; }
	elsif (/^no-bf$/)       { $no_bf=1; }
	elsif (/^no-cast$/)     { $no_cast=1; }
	elsif (/^no-md2$/)      { $no_md2=1; }
	elsif (/^no-md4$/)      { $no_md4=1; }
	elsif (/^no-md5$/)      { $no_md5=1; }
	elsif (/^no-sha$/)      { $no_sha=1; }
	elsif (/^no-ripemd$/)   { $no_ripemd=1; }
	elsif (/^no-mdc2$/)     { $no_mdc2=1; }
	elsif (/^no-rsa$/)      { $no_rsa=1; }
	elsif (/^no-dsa$/)      { $no_dsa=1; }
	elsif (/^no-dh$/)       { $no_dh=1; }
	elsif (/^no-hmac$/)	{ $no_hmac=1; }
	}


# If no platform is given, assume WIN32
if ($W32 + $W16 + $VMS == 0) {
	$W32 = 1;
}

# Add extra knowledge
if ($W16) {
	$no_fp_api=1;
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

my $ssl="ssl/ssl.h";

my $crypto ="crypto/crypto.h";
$crypto.=" crypto/des/des.h" unless $no_des;
$crypto.=" crypto/idea/idea.h" unless $no_idea;
$crypto.=" crypto/rc4/rc4.h" unless $no_rc4;
$crypto.=" crypto/rc5/rc5.h" unless $no_rc5;
$crypto.=" crypto/rc2/rc2.h" unless $no_rc2;
$crypto.=" crypto/bf/blowfish.h" unless $no_bf;
$crypto.=" crypto/cast/cast.h" unless $no_cast;
$crypto.=" crypto/md2/md2.h" unless $no_md2;
$crypto.=" crypto/md4/md4.h" unless $no_md4;
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
$crypto.=" crypto/dso/dso.h";
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

my $symhacks="crypto/symhacks.h";

my @ssl_symbols = &do_defs("SSLEAY", $ssl, $symhacks);
my @crypto_symbols = &do_defs("LIBEAY", $crypto, $symhacks);

if ($do_update) {

if ($do_ssl == 1) {

	&maybe_add_info("SSLEAY",*ssl_list,@ssl_symbols);
	if ($do_rewrite == 1) {
		open(OUT, ">$ssl_num");
		&rewrite_numbers(*OUT,"SSLEAY",*ssl_list,@ssl_symbols);
		close OUT;
	} else {
		open(OUT, ">>$ssl_num");
	}
	&update_numbers(*OUT,"SSLEAY",*ssl_list,$max_ssl,@ssl_symbols);
	close OUT;
}

if($do_crypto == 1) {

	&maybe_add_info("LIBEAY",*crypto_list,@crypto_symbols);
	if ($do_rewrite == 1) {
		open(OUT, ">$crypto_num");
		&rewrite_numbers(*OUT,"LIBEAY",*crypto_list,@crypto_symbols);
	} else {
		open(OUT, ">>$crypto_num");
	}
	&update_numbers(*OUT,"LIBEAY",*crypto_list,$max_crypto,@crypto_symbols);
	close OUT;
} 

} elsif ($do_ctest || $do_ctestall) {

	print <<"EOF";

/* Test file to check all DEF file symbols are present by trying
 * to link to all of them. This is *not* intended to be run!
 */

int main()
{
EOF
	&print_test_file(*STDOUT,"SSLEAY",*ssl_list,$do_ctestall,@ssl_symbols)
		if $do_ssl == 1;

	&print_test_file(*STDOUT,"LIBEAY",*crypto_list,$do_ctestall,@crypto_symbols)
		if $do_crypto == 1;

	print "}\n";

} else {

	&print_def_file(*STDOUT,"SSLEAY",*ssl_list,@ssl_symbols)
		if $do_ssl == 1;

	&print_def_file(*STDOUT,"LIBEAY",*crypto_list,@crypto_symbols)
		if $do_crypto == 1;

}


sub do_defs
{
	my($name,$files,$symhacksfile)=@_;
	my $file;
	my @ret;
	my %syms;
	my %platform;		# For anything undefined, we assume ""
	my %kind;		# For anything undefined, we assume "FUNCTION"
	my %algorithm;		# For anything undefined, we assume ""
	my %rename;
	my $cpp;

	foreach $file (split(/\s+/,$symhacksfile." ".$files))
		{
		open(IN,"<$file") || die "unable to open $file:$!\n";
		my $line = "", my $def= "";
		my %tag = (
			(map { $_ => 0 } @known_platforms),
			(map { "NO_".$_ => 0 } @known_algorithms),
			NOPROTO		=> 0,
			PERL5		=> 0,
			_WINDLL		=> 0,
			CONST_STRICT	=> 0,
			TRUE		=> 1,
		);
		my $symhacking = $file eq $symhacksfile;
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

	    		$cpp = 1 if /^\#.*ifdef.*cplusplus/;
			if ($cpp) {
				$cpp = 0 if /^\#.*endif/;
				next;
	    		}

			s/\/\*.*?\*\///gs;                   # ignore comments
			s/{[^{}]*}//gs;                      # ignore {} blocks
			if (/^\#\s*ifndef (.*)/) {
				push(@tag,$1);
				$tag{$1}=-1;
			} elsif (/^\#\s*if !defined\(([^\)]+)\)/) {
				push(@tag,$1);
				$tag{$1}=-1;
			} elsif (/^\#\s*ifdef (.*)/) {
				push(@tag,$1);
				$tag{$1}=1;
			} elsif (/^\#\s*if defined\(([^\)]+)\)/) {
				push(@tag,$1);
				$tag{$1}=1;
			} elsif (/^\#\s*error\s+(\w+) is disabled\./) {
				if ($tag[$#tag] eq "NO_".$1) {
					$tag{$tag[$#tag]}=2;
				}
			} elsif (/^\#\s*endif/) {
				if ($tag{$tag[$#tag]}==2) {
					$tag{$tag[$#tag]}=-1;
				} else {
					$tag{$tag[$#tag]}=0;
				}
				pop(@tag);
			} elsif (/^\#\s*else/) {
				my $t=$tag[$#tag];
				$tag{$t}= -$tag{$t};
			} elsif (/^\#\s*if\s+1/) {
				# Dummy tag
				push(@tag,"TRUE");
				$tag{"TRUE"}=1;
			} elsif (/^\#\s*if\s+0/) {
				# Dummy tag
				push(@tag,"TRUE");
				$tag{"TRUE"}=-1;
			} elsif (/^\#\s*define\s+(\w+)\s+(\w+)/
				 && $symhacking) {
				my $s = $1;
				my $a =
				    $2.":".join(",", grep(!/^$/,
							  map { $tag{$_} == 1 ?
								    $_ : "" }
							  @known_platforms));
				$rename{$s} = $a;
			}
			if (/^\#/) {
				my @p = grep(!/^$/,
					     map { $tag{$_} == 1 ? $_ :
						       $tag{$_} == -1 ? "!".$_  : "" }
					     @known_platforms);
				my @a = grep(!/^$/,
					     map { $tag{"NO_".$_} == -1 ? $_ : "" }
					     @known_algorithms);
				$def .= "#INFO:".join(',',@p).":".join(',',@a).";";
				next;
			}
			if (/^\s*DECLARE_STACK_OF\s*\(\s*(\w*)\s*\)/) {
				next;
			} elsif (/^\s*DECLARE_PKCS12_STACK_OF\s*\(\s*(\w*)\s*\)/) {
				next;
			} elsif (/^\s*DECLARE_ASN1_SET_OF\s*\(\s*(\w*)\s*\)/) {
				next;
			} elsif (/^DECLARE_PEM_rw\s*\(\s*(\w*)\s*,/ ||
				 /^DECLARE_PEM_rw_cb\s*\(\s*(\w*)\s*,/ ) {
				# Things not in Win16
				$syms{"PEM_read_${1}"} = 1;
				$platform{"PEM_read_${1}"} = "!WIN16";
				$syms{"PEM_write_${1}"} = 1;
				$platform{"PEM_write_${1}"} = "!WIN16";
				# Things that are everywhere
				$syms{"PEM_read_bio_${1}"} = 1;
				$syms{"PEM_write_bio_${1}"} = 1;
				if ($1 eq "RSAPrivateKey" ||
				    $1 eq "RSAPublicKey" ||
				    $1 eq "RSA_PUBKEY") {
					$algorithm{"PEM_read_${1}"} = "RSA";
					$algorithm{"PEM_write_${1}"} = "RSA";
					$algorithm{"PEM_read_bio_${1}"} = "RSA";
					$algorithm{"PEM_write_bio_${1}"} = "RSA";
				}
				elsif ($1 eq "DSAPrivateKey" ||
				       $1 eq "DSAparams" ||
				       $1 eq "RSA_PUBKEY") {
					$algorithm{"PEM_read_${1}"} = "DSA";
					$algorithm{"PEM_write_${1}"} = "DSA";
					$algorithm{"PEM_read_bio_${1}"} = "DSA";
					$algorithm{"PEM_write_bio_${1}"} = "DSA";
				}
				elsif ($1 eq "DHparams") {
					$algorithm{"PEM_read_${1}"} = "DH";
					$algorithm{"PEM_write_${1}"} = "DH";
					$algorithm{"PEM_read_bio_${1}"} = "DH";
					$algorithm{"PEM_write_bio_${1}"} = "DH";
				}
			} elsif (/^DECLARE_PEM_write\s*\(\s*(\w*)\s*,/ ||
				     /^DECLARE_PEM_write_cb\s*\(\s*(\w*)\s*,/ ) {
				# Things not in Win16
				$syms{"PEM_write_${1}"} = 1;
				$platform{"PEM_write_${1}"} .= ",!WIN16";
				# Things that are everywhere
				$syms{"PEM_write_bio_${1}"} = 1;
				if ($1 eq "RSAPrivateKey" ||
				    $1 eq "RSAPublicKey" ||
				    $1 eq "RSA_PUBKEY") {
					$algorithm{"PEM_write_${1}"} = "RSA";
					$algorithm{"PEM_write_bio_${1}"} = "RSA";
				}
				elsif ($1 eq "DSAPrivateKey" ||
				       $1 eq "DSAparams" ||
				       $1 eq "RSA_PUBKEY") {
					$algorithm{"PEM_write_${1}"} = "DSA";
					$algorithm{"PEM_write_bio_${1}"} = "DSA";
				}
				elsif ($1 eq "DHparams") {
					$algorithm{"PEM_write_${1}"} = "DH";
					$algorithm{"PEM_write_bio_${1}"} = "DH";
				}
			} elsif (/^DECLARE_PEM_read\s*\(\s*(\w*)\s*,/ ||
				     /^DECLARE_PEM_read_cb\s*\(\s*(\w*)\s*,/ ) {
				# Things not in Win16
				$syms{"PEM_read_${1}"} = 1;
				$platform{"PEM_read_${1}"} .= ",!WIN16";
				# Things that are everywhere
				$syms{"PEM_read_bio_${1}"} = 1;
			} elsif (
				($tag{'TRUE'} != -1)
				&& ($tag{'CONST_STRICT'} != 1)
				 )
				{
					if (/\{|\/\*|\([^\)]*$/) {
						$line = $_;
					} else {
						$def .= $_;
					}
				}
			}
		close(IN);

		my $algs;
		my $plays;

		foreach (split /;/, $def) {
			my $s; my $k = "FUNCTION"; my $p; my $a;
			s/^[\n\s]*//g;
			s/[\n\s]*$//g;
			next if(/\#undef/);
			next if(/typedef\W/);
			next if(/\#define/);

			if (/^\#INFO:([^:]*):(.*)$/) {
				$plats = $1;
				$algs = $2;
				next;
			} elsif (/^\s*OPENSSL_EXTERN\s.*?(\w+)(\[[0-9]*\])*\s*$/) {
				$s = $1;
				$k = "VARIABLE";
			} elsif (/\(\*(\w*)\([^\)]+/) {
				$s = $1;
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
				$s = $1;
			} elsif (/\(/ and not (/=/)) {
				print STDERR "File $file: cannot parse: $_;\n";
				next;
			} else {
				next;
			}

			$syms{$s} = 1;
			$kind{$s} = $k;

			$p = $plats;
			$a = $algs;
			$a .= ",BF" if($s =~ /EVP_bf/);
			$a .= ",CAST" if($s =~ /EVP_cast/);
			$a .= ",DES" if($s =~ /EVP_des/);
			$a .= ",DSA" if($s =~ /EVP_dss/);
			$a .= ",IDEA" if($s =~ /EVP_idea/);
			$a .= ",MD2" if($s =~ /EVP_md2/);
			$a .= ",MD4" if($s =~ /EVP_md4/);
			$a .= ",MD5" if($s =~ /EVP_md5/);
			$a .= ",RC2" if($s =~ /EVP_rc2/);
			$a .= ",RC4" if($s =~ /EVP_rc4/);
			$a .= ",RC5" if($s =~ /EVP_rc5/);
			$a .= ",RIPEMD" if($s =~ /EVP_ripemd/);
			$a .= ",SHA" if($s =~ /EVP_sha/);
			$a .= ",RSA" if($s =~ /EVP_(Open|Seal)(Final|Init)/);
			$a .= ",RSA" if($s =~ /PEM_Seal(Final|Init|Update)/);
			$a .= ",RSA" if($s =~ /RSAPrivateKey/);
			$a .= ",RSA" if($s =~ /SSLv23?_((client|server)_)?method/);

			$platform{$s} .= ','.$p;
			$algorithm{$s} .= ','.$a;

			if (defined($rename{$s})) {
				(my $r, my $p) = split(/:/,$rename{$s});
				my @ip = map { /^!(.*)$/ ? $1 : "!".$_ } split /,/, $p;
				$syms{$r} = 1;
				$kind{$r} = $kind{$s}."(".$s.")";
				$algorithm{$r} = $algorithm{$s};
				$platform{$r} = $platform{$s}.",".$p;
				$platform{$s} .= ','.join(',', @ip).','.join(',', @ip);
			}
		}
	}

	# Prune the returned symbols

	$platform{"crypt"} .= ",!PERL5,!__FreeBSD__,!NeXT";

        delete $syms{"SSL_add_dir_cert_subjects_to_stack"};
        delete $syms{"bn_dump1"};

	$platform{"BIO_s_file_internal"} .= ",WIN16";
	$platform{"BIO_new_file_internal"} .= ",WIN16";
	$platform{"BIO_new_fp_internal"} .= ",WIN16";

	$platform{"BIO_s_file"} .= ",!WIN16";
	$platform{"BIO_new_file"} .= ",!WIN16";
	$platform{"BIO_new_fp"} .= ",!WIN16";

	$platform{"BIO_s_log"} .= ",!WIN32,!WIN16,!macintosh";

	if(exists $syms{"ERR_load_CRYPTO_strings"}) {
		$platform{"ERR_load_CRYPTO_strings"} .= ",!VMS,!WIN16";
		$syms{"ERR_load_CRYPTOlib_strings"} = 1;
		$platform{"ERR_load_CRYPTOlib_strings"} .= ",VMS,WIN16";
	}

	# Info we know about

	$platform{"RSA_PKCS1_RSAref"} = "RSAREF";
	$algorithm{"RSA_PKCS1_RSAref"} = "RSA";

	push @ret, map { $_."\\".&info_string($_,"EXIST",
					      $platform{$_},
					      $kind{$_},
					      $algorithm{$_}) } keys %syms;

	return(@ret);
}

sub info_string {
	(my $symbol, my $exist, my $platforms, my $kind, my $algorithms) = @_;

	my %a = defined($algorithms) ?
	    map { $_ => 1 } split /,/, $algorithms : ();
	my $pl = defined($platforms) ? $platforms : "";
	my %p = map { $_ => 0 } split /,/, $pl;
	my $k = defined($kind) ? $kind : "FUNCTION";
	my $ret;

	# We do this, because if there's code like the following, it really
	# means the function exists in all cases and should therefore be
	# everywhere.  By increasing and decreasing, we may attain 0:
	#
	# ifndef WIN16
	#    int foo();
	# else
	#    int _fat foo();
	# endif
	foreach $platform (split /,/, $pl) {
		if ($platform =~ /^!(.*)$/) {
			$p{$1}--;
		} else {
			$p{$platform}++;
		}
	}
	foreach $platform (keys %p) {
		if ($p{$platform} == 0) { delete $p{$platform}; }
	}

	delete $p{""};
	delete $a{""};

	$ret = $exist;
	$ret .= ":".join(',',map { $p{$_} < 0 ? "!".$_ : $_ } keys %p);
	$ret .= ":".$k;
	$ret .= ":".join(',',keys %a);
	return $ret;
}

sub maybe_add_info {
	(my $name, *nums, my @symbols) = @_;
	my $sym;
	my $new_info = 0;

	print STDERR "Updating $name info\n";
	foreach $sym (@symbols) {
		(my $s, my $i) = split /\\/, $sym;
		$i =~ s/^(.*?:.*?:\w+)(\(\w+\))?/$1/;
		if (defined($nums{$s})) {
			(my $n, my $dummy) = split /\\/, $nums{$s};
			if (!defined($dummy) || $i ne $dummy) {
				$nums{$s} = $n."\\".$i;
				$new_info++;
				#print STDERR "DEBUG: maybe_add_info for $s: \"$dummy\" => \"$i\"\n";
			}
		}
	}
	if ($new_info) {
		print STDERR "$new_info old symbols got an info update\n";
		if (!$do_rewrite) {
			print STDERR "You should do a rewrite to fix this.\n";
		}
	} else {
		print STDERR "No old symbols needed info update\n";
	}
}

sub print_test_file
{
	(*OUT,my $name,*nums,my @symbols)=@_;
	my $n = 1; my @e; my @r;
	my $sym; my $prev = ""; my $prefSSLeay;

	(@e)=grep(/^SSLeay\\.*?:.*?:FUNCTION/,@symbols);
	(@r)=grep(/^\w+\\.*?:.*?:FUNCTION/ && !/^SSLeay\\.*?:.*?:FUNCTION/,@symbols);
	@symbols=((sort @e),(sort @r));

	foreach $sym (@symbols) {
		(my $s, my $i) = $sym =~ /^(.*?)\\(.*)$/;
		if ($s ne $prev) {
			if (!defined($nums{$sym})) {
				printf STDERR "Warning: $sym does not have a number assigned\n"
						if(!$do_update);
			} else {
				$n=$nums{$s};
				print OUT "\t$s();\n";
			}
		}
		$prev = $s;	# To avoid duplicates...
	}
}

sub print_def_file
{
	(*OUT,my $name,*nums,my @symbols)=@_;
	my $n = 1; my @e; my @r;

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

	(@e)=grep(/^SSLeay\\.*?:.*?:FUNCTION/,@symbols);
	(@r)=grep(/^\w+\\.*?:.*?:FUNCTION/ && !/^SSLeay\\.*?:.*?:FUNCTION/,@symbols);
	@symbols=((sort @e),(sort @r));


	foreach $sym (@symbols) {
		(my $s, my $i) = $sym =~ /^(.*?)\\(.*)$/;
		if (!defined($nums{$s})) {
			printf STDERR "Warning: $s does not have a number assigned\n"
					if(!$do_update);
		} else {
			(my $n, my $i) = split /\\/, $nums{$s};
			my %pf = ();
			my @p = split(/,/, ($i =~ /^[^:]*:([^:]*):/,$1));
			my @a = split(/,/, ($i =~ /^[^:]*:[^:]*:[^:]*:([^:]*)/,$1));
			# @p_purged must contain hardware platforms only
			my @p_purged = ();
			foreach $ptmp (@p) {
				next if $ptmp =~ /^!?RSAREF$/;
				push @p_purged, $ptmp;
			}
			my $negatives = !!grep(/^!/,@p);
			# It is very important to check NT before W32
			if ((($NT && (!@p_purged
				      || (!$negatives && grep(/^WINNT$/,@p))
				      || ($negatives && !grep(/^!WINNT$/,@p))))
			     || ($W32 && (!@p_purged
					  || (!$negatives && grep(/^WIN32$/,@p))
					  || ($negatives && !grep(/^!WIN32$/,@p))))
			     || ($W16 && (!@p_purged
					  || (!$negatives && grep(/^WIN16$/,@p))
					  || ($negatives && !grep(/^!WIN16$/,@p)))))
			    && (!@p
				|| (!$negatives
				    && ($rsaref || !grep(/^RSAREF$/,@p)))
				|| ($negatives
				    && (!$rsaref || !grep(/^!RSAREF$/,@p))))
			    && (!@a || (!$no_rc2 || !grep(/^RC2$/,@a)))
			    && (!@a || (!$no_rc4 || !grep(/^RC4$/,@a)))
			    && (!@a || (!$no_rc5 || !grep(/^RC5$/,@a)))
			    && (!@a || (!$no_idea || !grep(/^IDEA$/,@a)))
			    && (!@a || (!$no_des || !grep(/^DES$/,@a)))
			    && (!@a || (!$no_bf || !grep(/^BF$/,@a)))
			    && (!@a || (!$no_cast || !grep(/^CAST$/,@a)))
			    && (!@a || (!$no_md2 || !grep(/^MD2$/,@a)))
			    && (!@a || (!$no_md4 || !grep(/^MD4$/,@a)))
			    && (!@a || (!$no_md5 || !grep(/^MD5$/,@a)))
			    && (!@a || (!$no_sha || !grep(/^SHA$/,@a)))
			    && (!@a || (!$no_ripemd || !grep(/^RIPEMD$/,@a)))
			    && (!@a || (!$no_mdc2 || !grep(/^MDC2$/,@a)))
			    && (!@a || (!$no_rsa || !grep(/^RSA$/,@a)))
			    && (!@a || (!$no_dsa || !grep(/^DSA$/,@a)))
			    && (!@a || (!$no_dh || !grep(/^DH$/,@a)))
			    && (!@a || (!$no_hmac || !grep(/^HMAC$/,@a)))
			    && (!@a || (!$no_fp_api || !grep(/^FP_API$/,@a)))
			    ) {
				printf OUT "    %s%-40s@%d\n",($W32)?"":"_",$s,$n;
#			} else {
#				print STDERR "DEBUG: \"$sym\" (@p):",
#				" rsaref:", !!(!@p
#					       || (!$negatives
#						   && ($rsaref || !grep(/^RSAREF$/,@p)))
#					       || ($negatives
#						   && (!$rsaref || !grep(/^!RSAREF$/,@p))))?1:0,
#				" 16:", !!($W16 && (!@p_purged
#						    || (!$negatives && grep(/^WIN16$/,@p))
#						    || ($negatives && !grep(/^!WIN16$/,@p)))),
#				" 32:", !!($W32 && (!@p_purged
#						    || (!$negatives && grep(/^WIN32$/,@p))
#						    || ($negatives && !grep(/^!WIN32$/,@p)))),
#				" NT:", !!($NT && (!@p_purged
#						   || (!$negatives && grep(/^WINNT$/,@p))
#						   || ($negatives && !grep(/^!WINNT$/,@p)))),
#				"\n";
			}
		}
	}
	printf OUT "\n";
}

sub load_numbers
{
	my($name)=@_;
	my(@a,%ret);

	$max_num = 0;
	$num_noinfo = 0;
	$prev = "";

	open(IN,"<$name") || die "unable to open $name:$!\n";
	while (<IN>) {
		chop;
		s/#.*$//;
		next if /^\s*$/;
		@a=split;
		if (defined $ret{$a[0]}) {
			print STDERR "Warning: Symbol '",$a[0],"' redefined. old=",$ret{$a[0]},", new=",$a[1],"\n";
		}
		if ($max_num > $a[1]) {
			print STDERR "Warning: Number decreased from ",$max_num," to ",$a[1],"\n";
		}
		if ($max_num == $a[1]) {
			# This is actually perfectly OK
			#print STDERR "Warning: Symbol ",$a[0]," has same number as previous ",$prev,": ",$a[1],"\n";
		}
		if ($#a < 2) {
			# Existence will be proven later, in do_defs
			$ret{$a[0]}=$a[1];
			$num_noinfo++;
		} else {
			$ret{$a[0]}=$a[1]."\\".$a[2]; # \\ is a special marker
		}
		$max_num = $a[1] if $a[1] > $max_num;
		$prev=$a[0];
	}
	if ($num_noinfo) {
		print STDERR "Warning: $num_noinfo symbols were without info.";
		if ($do_rewrite) {
			printf STDERR "  The rewrite will fix this.\n";
		} else {
			printf STDERR "  You should do a rewrite to fix this.\n";
		}
	}
	close(IN);
	return(%ret);
}

sub parse_number
{
	(my $str, my $what) = @_;
	(my $n, my $i) = split(/\\/,$str);
	if ($what eq "n") {
		return $n;
	} else {
		return $i;
	}
}

sub rewrite_numbers
{
	(*OUT,$name,*nums,@symbols)=@_;
	my $thing;

	print STDERR "Rewriting $name\n";

	my @r = grep(/^\w+\\.*?:.*?:\w+\(\w+\)/,@symbols);
	my $r; my %r; my %rsyms;
	foreach $r (@r) {
		(my $s, my $i) = split /\\/, $r;
		my $a = $1 if $i =~ /^.*?:.*?:\w+\((\w+)\)/;
		$i =~ s/^(.*?:.*?:\w+)\(\w+\)/$1/;
		$r{$a} = $s."\\".$i;
		$rsyms{$s} = 1;
	}

	my @s=sort { &parse_number($nums{$a},"n") <=> &parse_number($nums{$b},"n") } keys %nums;
	foreach $sym (@s) {
		(my $n, my $i) = split /\\/, $nums{$sym};
		next if defined($i) && $i =~ /^.*?:.*?:\w+\(\w+\)/;
		next if defined($rsyms{$sym});
		$i="NOEXIST::FUNCTION:" if !defined($i) || $i eq "";
		printf OUT "%s%-40s%d\t%s\n","",$sym,$n,$i;
		if (exists $r{$sym}) {
			(my $s, $i) = split /\\/,$r{$sym};
			printf OUT "%s%-40s%d\t%s\n","",$s,$n,$i;
		}
	}
}

sub update_numbers
{
	(*OUT,$name,*nums,my $start_num, my @symbols)=@_;
	my $new_syms = 0;

	print STDERR "Updating $name numbers\n";

	my @r = grep(/^\w+\\.*?:.*?:\w+\(\w+\)/,@symbols);
	my $r; my %r; my %rsyms;
	foreach $r (@r) {
		(my $s, my $i) = split /\\/, $r;
		my $a = $1 if $i =~ /^.*?:.*?:\w+\((\w+)\)/;
		$i =~ s/^(.*?:.*?:\w+)\(\w+\)/$1/;
		$r{$a} = $s."\\".$i;
		$rsyms{$s} = 1;
	}

	foreach $sym (@symbols) {
		(my $s, my $i) = $sym =~ /^(.*?)\\(.*)$/;
		next if $i =~ /^.*?:.*?:\w+\(\w+\)/;
		next if defined($rsyms{$sym});
		die "ERROR: Symbol $sym had no info attached to it."
		    if $i eq "";
		if (!exists $nums{$s}) {
			$new_syms++;
			printf OUT "%s%-40s%d\t%s\n","",$s, ++$start_num,$i;
			if (exists $r{$s}) {
				($s, $i) = split /\\/,$r{$s};
				printf OUT "%s%-40s%d\t%s\n","",$s, $start_num,$i;
			}
		}
	}
	if($new_syms) {
		print STDERR "$new_syms New symbols added\n";
	} else {
		print STDERR "No New symbols Added\n";
	}
}

sub check_existing
{
	(*nums, my @symbols)=@_;
	my %existing; my @remaining;
	@remaining=();
	foreach $sym (@symbols) {
		(my $s, my $i) = $sym =~ /^(.*?)\\(.*)$/;
		$existing{$s}=1;
	}
	foreach $sym (keys %nums) {
		if (!exists $existing{$sym}) {
			push @remaining, $sym;
		}
	}
	if(@remaining) {
		print STDERR "The following symbols do not seem to exist:\n";
		foreach $sym (@remaining) {
			print STDERR "\t",$sym,"\n";
		}
	}
}

