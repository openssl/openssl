#!/usr/local/bin/perl
#
# Mingw32.pl -- Mingw32 with GNU cp (Mingw32f.pl uses DOS tools) 
#

$o='/';
$cp='cp';
$rm='rem'; # use 'rm -f' if using GNU file utilities
$mkdir='gmkdir';

# gcc wouldn't accept backslashes in paths
#$o='\\';
#$cp='copy';
#$rm='del';

# C compiler stuff

$cc='gcc';
if ($debug)
	{ $cflags="-DL_ENDIAN -g2 -ggdb"; }
else
	{ $cflags="-DL_ENDIAN -fomit-frame-pointer -O3 -m486 -Wall"; }

if ($gaswin and !$no_asm)
	{
        $bn_asm_obj='$(OBJ_D)/bn-win32.o';
        $bn_asm_src='crypto/bn/asm/bn-win32.s';
        $des_enc_obj='$(OBJ_D)/d-win32.o $(OBJ_D)/y-win32.o';
        $des_enc_src='crypto/des/asm/d-win32.s crypto/des/asm/y-win32.s';
        $bf_enc_obj='$(OBJ_D)/b-win32.o';
        $bf_enc_src='crypto/bf/asm/b-win32.s';
#       $cast_enc_obj='$(OBJ_D)/c-win32.o';
#       $cast_enc_src='crypto/cast/asm/c-win32.s';
        $rc4_enc_obj='$(OBJ_D)/r4-win32.o';
        $rc4_enc_src='crypto/rc4/asm/r4-win32.s';
        $rc5_enc_obj='$(OBJ_D)/r5-win32.o';
        $rc5_enc_src='crypto/rc5/asm/r5-win32.s';
        $md5_asm_obj='$(OBJ_D)/m5-win32.o';
        $md5_asm_src='crypto/md5/asm/m5-win32.s';
        $rmd160_asm_obj='$(OBJ_D)/rm-win32.o';
        $rmd160_asm_src='crypto/ripemd/asm/rm-win32.s';
        $sha1_asm_obj='$(OBJ_D)/s1-win32.o';
        $sha1_asm_src='crypto/sha/asm/s1-win32.s';
	$cflags.=" -DBN_ASM -DMD5_ASM -DSHA1_ASM";
	}


$obj='.o';
$ofile='-o ';

# EXE linking stuff
$link='${CC}';
$lflags='${CFLAGS}';
$efile='-o ';
$exep='';
$ex_libs="-lwsock32 -lgdi32";

# static library stuff
$mklib='ar r';
$mlflags='';
$ranlib='ranlib';
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
