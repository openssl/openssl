#!/usr/local/bin/perl

$mkprog='mklinks';
$rmprog='rmlinks';

print "#ifndef NOPROTO\n";

grep(s/^asn1pars$/asn1parse/,@ARGV);

foreach (@ARGV)
	{ printf "extern int %s_main(int argc,char *argv[]);\n",$_; }
print "#else\n";
foreach (@ARGV)
	{ printf "extern int %s_main();\n",$_; }
print "#endif\n";


print <<'EOF';

#ifdef SSLEAY_SRC

#define FUNC_TYPE_GENERAL	1
#define FUNC_TYPE_MD		2
#define FUNC_TYPE_CIPHER	3

typedef struct {
	int type;
	char *name;
	int (*func)();
	} FUNCTION;

FUNCTION functions[] = {
EOF

foreach (@ARGV)
	{
	push(@files,$_);
	$str="\t{FUNC_TYPE_GENERAL,\"$_\",${_}_main},\n";
	if (($_ =~ /^s_/) || ($_ =~ /^ciphers$/))
		{ print "#if !defined(NO_SOCK) && !(defined(NO_SSL2) && defined(O_SSL3))\n${str}#endif\n"; } 
	elsif ( ($_ =~ /^rsa$/) || ($_ =~ /^genrsa$/) ||
		($_ =~ /^req$/) || ($_ =~ /^ca$/) || ($_ =~ /^x509$/))
		{ print "#ifndef NO_RSA\n${str}#endif\n";  }
	elsif ( ($_ =~ /^dsa$/) || ($_ =~ /^gendsa$/) || ($_ =~ /^dsaparam$/))
		{ print "#ifndef NO_DSA\n${str}#endif\n"; }
	elsif ( ($_ =~ /^dh$/) || ($_ =~ /^gendh$/))
		{ print "#ifndef NO_DH\n${str}#endif\n"; }
	else
		{ print $str; }
	}

foreach ("md2","md5","sha","sha1","mdc2","rmd160")
	{
	push(@files,$_);
	printf "\t{FUNC_TYPE_MD,\"%s\",dgst_main},\n",$_;
	}

foreach (
	"base64",
	"des", "des3", "desx", "idea", "rc4", "rc2","bf","cast","rc5",
	"des-ecb", "des-ede",    "des-ede3",
	"des-cbc", "des-ede-cbc","des-ede3-cbc",
	"des-cfb", "des-ede-cfb","des-ede3-cfb",
	"des-ofb", "des-ede-ofb","des-ede3-ofb",
	"idea-cbc","idea-ecb",   "idea-cfb", "idea-ofb",
	"rc2-cbc", "rc2-ecb",    "rc2-cfb",  "rc2-ofb",
	"bf-cbc",  "bf-ecb",     "bf-cfb",   "bf-ofb",
	"cast5-cbc","cast5-ecb", "cast5-cfb","cast5-ofb",
	"cast-cbc", "rc5-cbc",   "rc5-ecb",  "rc5-cfb",  "rc5-ofb")
	{
	push(@files,$_);

	$t=sprintf("\t{FUNC_TYPE_CIPHER,\"%s\",enc_main},\n",$_);
	if    ($_ =~ /des/)  { $t="#ifndef NO_DES\n${t}#endif\n"; }
	elsif ($_ =~ /idea/) { $t="#ifndef NO_IDEA\n${t}#endif\n"; }
	elsif ($_ =~ /rc4/)  { $t="#ifndef NO_RC4\n${t}#endif\n"; }
	elsif ($_ =~ /rc2/)  { $t="#ifndef NO_RC2\n${t}#endif\n"; }
	elsif ($_ =~ /bf/)   { $t="#ifndef NO_BLOWFISH\n${t}#endif\n"; }
	elsif ($_ =~ /cast/) { $t="#ifndef NO_CAST\n${t}#endif\n"; }
	elsif ($_ =~ /rc5/)  { $t="#ifndef NO_RC5\n${t}#endif\n"; }
	print $t;
	}

print "\t{0,NULL,NULL}\n\t};\n";
print "#endif\n\n";

open(OUT,">$mkprog") || die "unable to open '$prog':$!\n";
print OUT "#!/bin/sh\nfor i in ";
foreach (@files)
	{ print OUT $_." "; }
print OUT <<'EOF';

do
echo making symlink for $i
/bin/rm -f $i
ln -s ssleay $i
done
EOF
close(OUT);
chmod(0755,$mkprog);

open(OUT,">$rmprog") || die "unable to open '$prog':$!\n";
print OUT "#!/bin/sh\nfor i in ";
foreach (@files)
	{ print OUT $_." "; }
print OUT <<'EOF';

do
echo removing $i
/bin/rm -f $i
done
EOF
close(OUT);
chmod(0755,$rmprog);
