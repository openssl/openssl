#!/usr/local/bin/perl
#
# OS2-EMX.pl - for EMX GCC on OS/2
#

$o='\\';
$cp='copy';
$rm='rm -f';

# C compiler stuff

$cc='gcc';
$cflags="-DL_ENDIAN -O3 -fomit-frame-pointer -m486 -Zmt -Wall ";

if ($debug) { 
	$cflags.="-g "; 
}

$obj='.o';
$ofile='-o ';

# EXE linking stuff
$link='${CC}';
$lflags='${CFLAGS} -Zbsd-signals';
$efile='-o ';
$exep='.exe';
$ex_libs="-lsocket";

# static library stuff
$mklib='ar r';
$mlflags='';
$ranlib="ar s";
$plib='lib';
$libp=".a";
$shlibp=".a";
$lfile='';

$asm='as';
$afile='-o ';
$bn_asm_obj="";
$bn_asm_src="";
$des_enc_obj="";
$des_enc_src="";
$bf_enc_obj="";
$bf_enc_src="";

if (!$no_asm)
	{
	$bn_asm_obj='crypto\bn\asm\bn-os2.o crypto\bn\asm\co-os2.o';
	$bn_asm_src='crypto\bn\asm\bn-os2.asm crypto\bn\asm\co-os2.asm';
	$des_enc_obj='crypto\des\asm\d-os2.o crypto\des\asm\y-os2.o';
	$des_enc_src='crypto\des\asm\d-os2.asm crypto\des\asm\y-os2.asm';
	$bf_enc_obj='crypto\bf\asm\b-os2.o';
	$bf_enc_src='crypto\bf\asm\b-os2.asm';
	$cast_enc_obj='crypto\cast\asm\c-os2.o';
	$cast_enc_src='crypto\cast\asm\c-os2.asm';
	$rc4_enc_obj='crypto\rc4\asm\r4-os2.o';
	$rc4_enc_src='crypto\rc4\asm\r4-os2.asm';
	$rc5_enc_obj='crypto\rc5\asm\r5-os2.o';
	$rc5_enc_src='crypto\rc5\asm\r5-os2.asm';
	$md5_asm_obj='crypto\md5\asm\m5-os2.o';
	$md5_asm_src='crypto\md5\asm\m5-os2.asm';
	$sha1_asm_obj='crypto\sha\asm\s1-os2.o';
	$sha1_asm_src='crypto\sha\asm\s1-os2.asm';
	$rmd160_asm_obj='crypto\ripemd\asm\rm-os2.o';
	$rmd160_asm_src='crypto\ripemd\asm\rm-os2.asm';
	}

sub do_lib_rule
	{
	local($obj,$target,$name,$shlib)=@_;
	local($ret,$_,$Name);

	$target =~ s/\//$o/g if $o ne '/';
	$target="$target";
	($Name=$name) =~ tr/a-z/A-Z/;

	$ret.="$target: \$(${Name}OBJ)\n";
	$ret.="\t\$(RM) $target\n";
	$ret.="\t\$(MKLIB) $target \$(${Name}OBJ)\n";
	$ret.="\t\$(RANLIB) $target\n\n";
	}

sub do_link_rule
	{
	local($target,$files,$dep_libs,$libs)=@_;
	local($ret,$_);
	
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($target);
	$ret.="$target: $files $dep_libs\n";
	$ret.="\t\$(LINK) ${efile}$target \$(LFLAGS) $files $libs\n\n";
	return($ret);
	}

1;
