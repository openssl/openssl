#!/usr/local/bin/perl
# VCw16lib.pl - the file for Visual C++ 1.52b for windows, static libraries
#

$o='\\';
$cp='copy';
$rm='del';

# C compiler stuff
$cc='bcc';

if ($debug)
	{ $op="-v "; }
else	{ $op="-O "; }

$cflags="-d -ml $op -DL_ENDIAN";
# I add the stack opt
$base_lflags="/c /C";
$lflags="$base_lflags";

if ($win16)
	{
	$shlib=1;
	$cflags.=" -DOPENSSL_SYSNAME_WIN16";
	$app_cflag="-W";
	$lib_cflag="-WD";
	$lflags.="/Twe";
	}
else
	{
	$cflags.=" -DOENSSL_SYSNAME_MSDOS";
	$lflags.=" /Tde";
	}

if ($shlib)
	{
	$mlflags=" /Twd $base_lflags"; # stack if defined in .def file
	$libs="libw ldllcew";
	$no_asm=1;
	}
else
	{ $mlflags=''; }

$obj='.obj';
$ofile="-o";

# EXE linking stuff
$link="tlink";
$efile="";
$exep='.exe';
$ex_libs="CL";
$ex_libs.=$no_sock?"":" winsock.lib";

$app_ex_obj="C0L.obj ";
$shlib_ex_obj="" if ($shlib);

# static library stuff
$mklib='tlib';
$ranlib='echo no ranlib';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='';

$asm='bcc -c -B -Tml';
$afile='/o';
if ($no_asm || $fips)
	{
	$bn_asm_obj='';
	$bn_asm_src='';
	}
elsif ($asmbits == 32)
	{
	$bn_asm_obj='crypto\bn\asm\x86w32.obj';
	$bn_asm_src='crypto\bn\asm\x86w32.asm';
	}
else
	{
	$bn_asm_obj='crypto\bn\asm\x86w16.obj';
	$bn_asm_src='crypto\bn\asm\x86w16.asm';
	}

sub do_lib_rule
	{
	local($target,$name,$shlib)=@_;
	local($ret,$Name);

	$taget =~ s/\//$o/g if $o ne '/';
	($Name=$name) =~ tr/a-z/A-Z/;

	$ret.="$target: \$(${Name}OBJ)\n";
	$ret.="\t\$(RM) \$(O_$Name)\n";

	# Due to a pathetic line length limit, I unwrap the args.
	local($lib_names)="";
	local($dll_names)="";
	foreach $_ (sort split(/\s+/,$Vars{"${Name}OBJ"}))
		{
		$lib_names.="  +$_ &\n";
		$dll_names.="  $_\n";
		}

	if (!$shlib)
		{
		$ret.="\t\$(MKLIB) $target & <<|\n$lib_names\n,\n|\n";
		}
	else
		{
		local($ex)=($Name eq "SSL")?' $(L_CRYPTO) winsock':"";
		$ret.="\t\$(LINK) \$(MLFLAGS) @&&|\n";
		$ret.=$dll_names;
		$ret.="\n  $target\n\n  $ex $libs\nms$o${name}16.def;\n|\n";
		($out_lib=$target) =~ s/O_/L_/;
		$ret.="\timplib /nowep $out_lib $target\n\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	local($target,$files,$dep_libs,$libs,$sha1file,$openssl)=@_;
	local($ret,$f,$_,@f);

	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($target);
	$ret.="$target: $files $dep_libs\n";
	$ret.="  \$(LINK) @&&|";
	
	# Due to a pathetic line length limit, I have to unwrap the args.
	$ret.=" \$(LFLAGS) ";
	if ($files =~ /\(([^)]*)\)$/)
		{
		$ret.=" \$(APP_EX_OBJ)";
		foreach $_ (sort split(/\s+/,$Vars{$1}))
			{ $ret.="\n  $r $_ +"; }
		chop($ret);
		$ret.="\n";
		}
	else
		{ $ret.="\n $r \$(APP_EX_OBJ) $files\n"; }
	$ret.="  $target\n\n  $libs\n\n|\n";
	if (defined $sha1file)
		{
		$ret.="  $openssl sha1 -hmac etaonrishdlcupfm -binary $target > $sha1file";
		}
	$ret.="\n";
	return($ret);
	}

1;
