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

