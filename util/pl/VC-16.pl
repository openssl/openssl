#!/usr/local/bin/perl
# VCw16lib.pl - the file for Visual C++ 1.52b for windows, static libraries
#

$ssl=	"ssleay16";
$crypto="libeay16";

$o='\\';
$cp='copy';
$rm='del';

# C compiler stuff
$cc='cl';

$out_def="out16";
$tmp_def="tmp16";
$inc_def="inc16";

if ($debug)
	{
	$op="/Od /Zi /Zd";
	$base_lflags="/CO";
	}
else	{
	$op="/G2 /f- /Ocgnotb2";
	}
$base_lflags.=" /FARCALL /NOLOGO /NOD /SEG:1024 /ONERROR:NOEXE /NOE /PACKC:60000";
if ($win16) { $base_lflags.=" /PACKD:60000"; }

$cflags="/ALw /Gx- /Gt256 /Gf $op /W3 /WX -DL_ENDIAN /nologo";
# I add the stack opt
$lflags="$base_lflags /STACK:20000";

if ($win16)
	{
	$cflags.=" -DOPENSSL_SYSNAME_WIN16";
	$app_cflag="/Gw /FPi87";
	$lib_cflag="/Gw";
	$lib_cflag.=" -D_WINDLL -D_DLL" if $shlib;
	$lib_cflag.=" -DWIN16TTY" if !$shlib;
	$lflags.=" /ALIGN:256";
	$ex_libs.="oldnames llibcewq libw";
	}
else
	{
	$no_sock=1;
	$cflags.=" -DMSDOS";
	$lflags.=" /EXEPACK";
	$ex_libs.="oldnames.lib llibce.lib";
	}

if ($shlib)
	{
	$mlflags="$base_lflags";
	$libs="oldnames ldllcew libw";
	$shlib_ex_obj="";
#	$no_asm=1;
	$out_def="out16dll";
	$tmp_def="tmp16dll";
	}
else
	{ $mlflags=''; }

$app_ex_obj="";

$obj='.obj';
$ofile="/Fo";

# EXE linking stuff
$link="link";
$efile="";
$exep='.exe';
$ex_libs.=$no_sock?"":" winsock";

# static library stuff
$mklib='lib /PAGESIZE:1024';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='';

$asm='ml /Cp /c /Cx';
$afile='/Fo';

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm && !$fips)
	{
	if ($asmbits == 32)
		{
		$bn_asm_obj='crypto\bn\asm\x86w32.obj';
		$bn_asm_src='crypto\bn\asm\x86w32.asm';
		}
	else
		{
		$bn_asm_obj='crypto\bn\asm\x86w16.obj';
		$bn_asm_src='crypto\bn\asm\x86w16.asm';
		}
	}

sub do_lib_rule
	{
	local($objs,$target,$name,$shlib)=@_;
	local($ret,$Name);

	$taget =~ s/\//$o/g if $o ne '/';
	($Name=$name) =~ tr/a-z/A-Z/;

#	$target="\$(LIB_D)$o$target";
	$ret.="$target: $objs\n";
#	$ret.="\t\$(RM) \$(O_$Name)\n";

	# Due to a pathetic line length limit, I unwrap the args.
	local($lib_names)="";
	local($dll_names)="  \$(SHLIB_EX_OBJ) +\n";
	($obj)= ($objs =~ /\((.*)\)/);
	foreach $_ (sort split(/\s+/,$Vars{$obj}))
		{
		$lib_names.="+$_ &\n";
		$dll_names.="  $_ +\n";
		}

	if (!$shlib)
		{
		$ret.="\tdel $target\n";
		$ret.="\t\$(MKLIB) @<<\n$target\ny\n$lib_names\n\n<<\n";
		}
	else
		{
		local($ex)=($target =~ /O_SSL/)?'$(L_CRYPTO)':"";
		$ex.=' winsock';
		$ret.="\t\$(LINK) \$(MLFLAGS) @<<\n";
		$ret.=$dll_names;
		$ret.="\n  $target\n\n  $ex $libs\nms$o${name}.def;\n<<\n";
		($out_lib=$target) =~ s/O_/L_/;
		$ret.="\timplib /noignorecase /nowep $out_lib $target\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	local($target,$files,$dep_libs,$libs,$sha1file,$openssl)=@_;
	local($ret,$f,$_,@f);
	
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	$ret.="  \$(LINK) \$(LFLAGS) @<<\n";
	
	# Due to a pathetic line length limit, I have to unwrap the args.
	if ($files =~ /\(([^)]*)\)$/)
		{
		@a=('$(APP_EX_OBJ)');
		push(@a,sort split(/\s+/,$Vars{$1}));
		for $_ (@a)
			{ $ret.="  $_ +\n"; }
		}
	else
		{ $ret.="  \$(APP_EX_OBJ) $files"; }
	$ret.="\n  $target\n\n  $libs\n\n<<\n";
	if (defined $sha1file)
		{
		$ret.="  $openssl sha1 -hmac etaonrishdlcupfm -binary $target > $sha1file";
		}
	$ret.="\n";
	return($ret);
	}

1;
