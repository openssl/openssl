#!/usr/local/bin/perl
# VCw32lib.pl - the file for Visual C++ 4.[01] for windows NT, static libraries
#

$ssl=	"ssleay32";
$crypto="libeay32";
$RSAref="RSAref32";

$o='\\';
$cp='copy';
$rm='del';

# C compiler stuff
$cc='cl';
$cflags='/W3 /WX /G5 /Ox /O2 /Ob2 /Gs0 /GF /Gy /nologo -DWIN32 -DL_ENDIAN';
$lflags="/nologo /subsystem:console /machine:I386 /opt:ref";
$mlflags='';
if ($debug)
	{
	$cflags="/W3 /WX /Zi /Yd /Od /nologo -DWIN32 -D_DEBUG -DL_ENDIAN";
	$lflags.=" /debug";
	$mlflags.=' /debug';
	}
$obj='.obj';
$ofile="/Fo";

# EXE linking stuff
$link="link";
$efile="/out:";
$exep='.exe';
if ($no_sock)
	{ $ex_libs=""; }
else	{ $ex_libs="wsock32.lib user32.lib gdi32.lib"; }

# static library stuff
$mklib='lib';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='/out:';

$shlib_ex_obj="";
$app_ex_obj="setargv.obj";

$asm='ml /Cp /coff /c /Cx';
$afile='/Fo';

$bn_mulw_obj='';
$bn_mulw_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm)
	{
	$bn_mulw_obj='crypto\bn\asm\x86nt32.obj';
	$bn_mulw_src='crypto\bn\asm\x86nt32.asm';
	$des_enc_obj='crypto\des\asm\d-win32.obj crypto\des\asm\c-win32.obj';
	$des_enc_src='crypto\des\asm\d-win32.asm crypto\des\asm\c-win32.asm';
	$bf_enc_obj='crypto\bf\asm\b-win32.obj';
	$bf_enc_src='crypto\bf\asm\b-win32.asm';
	}

if ($shlib)
	{
	$mlflags.=" $lflags /dll";
	$cflags.=" /MD";
	$cflags.="d" if ($debug);
	$lib_cflag=" /GD";
	}

sub do_lib_rule
	{
	local($objs,$target,$name,$shlib)=@_;
	local($ret,$Name);

	$taget =~ s/\//$o/g if $o ne '/';
	($Name=$name) =~ tr/a-z/A-Z/;

	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ret.="\t\$(MKLIB) $lfile$target @<<\n  $objs\n<<\n";
		}
	else
		{
		local($ex)=($target eq '$(O_SSL)')?' $(L_CRYPTO)':'';
		$ex.=' wsock32.lib gdi32.lib';
		$ret.="\t\$(LINK) \$(MLFLAGS) $efile$target /def:ms/${Name}.def @<<\n  \$(SHLIB_EX_OBJ) $objs $ex\n<<\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	local($target,$files,$dep_libs,$libs)=@_;
	local($ret,$_);
	
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	$ret.="  \$(LINK) \$(LFLAGS) $efile$target @<<\n";
	$ret.="  \$(APP_EX_OBJ) $files $libs\n<<\n\n";
	return($ret);
	}

1;
