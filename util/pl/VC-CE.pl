#!/usr/local/bin/perl
# VC-CE.pl - the file for eMbedded Visual C++ 3.0 for windows CE, static libraries
#

$ssl=	"ssleay32";
$crypto="libeay32";
$RSAref="RSAref32";

$o='\\';
$cp='copy nul+';	# Timestamps get stuffed otherwise
$rm='del';

# C compiler stuff
$cc='$(CC)';
$cflags=' /W3 /WX /Ox /O2 /Ob2 /Gs0 /GF /Gy /nologo $(WCETARGETDEFS) -DUNICODE -D_UNICODE -DWIN32 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -DNO_CHMOD -I$(WCECOMPAT)/include';
$lflags='/nologo /subsystem:windowsce,$(WCELDVERSION) /machine:$(WCELDMACHINE) /opt:ref';
$mlflags='';

$out_def='out32_$(TARGETCPU)';
$tmp_def='tmp32_$(TARGETCPU)';
$inc_def="inc32";

if ($debug)
	{
	$cflags=" /MDd /W3 /WX /Zi /Yd /Od /nologo -DWIN32 -D_DEBUG -DL_ENDIAN -DWIN32_LEAN_AND_MEAN -DDEBUG -DDSO_WIN32";
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
else	{ $ex_libs='winsock.lib $(WCECOMPAT)/lib/wcecompatex.lib $(WCELDFLAGS)'; }

# static library stuff
$mklib='lib';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='/out:';

$shlib_ex_obj="";
#$app_ex_obj="setargv.obj";
$app_ex_obj="";

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if ($shlib)
	{
	$mlflags.=" $lflags /dll";
#	$cflags =~ s| /MD| /MT|;
	$lib_cflag=" -D_WINDLL -D_DLL";
	$out_def='out32dll_$(TARGETCPU)';
	$tmp_def='tmp32dll_$(TARGETCPU)';
	}

$cflags.=" /Fd$out_def";

sub do_lib_rule
	{
	local($objs,$target,$name,$shlib)=@_;
	local($ret,$Name);

	$taget =~ s/\//$o/g if $o ne '/';
	($Name=$name) =~ tr/a-z/A-Z/;

#	$target="\$(LIB_D)$o$target";
	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ex =' ';
		$ret.="\t\$(MKLIB) $lfile$target @<<\n  $objs $ex\n<<\n";
		}
	else
		{
		local($ex)=($target =~ /O_SSL/)?' $(L_CRYPTO)':'';
#		$ex.=' winsock.lib coredll.lib $(WCECOMPAT)/lib/wcecompatex.lib';
		$ex.=' winsock.lib $(WCECOMPAT)/lib/wcecompatex.lib';
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
