#!/usr/local/bin/perl
# VCw16lib.pl - the file for Visual C++ 1.52b for windows, static libraries
#

$o='\\';
$cp='copy';
$rm='del';

# C compiler stuff
$cc='bcc32';

if ($debug)
	{ $op="-v "; }
else	{ $op="-O "; }

$cflags="-d $op -DL_ENDIAN ";
# I add the stack opt
$base_lflags="-c";
$lflags="$base_lflags";

$cflags.=" -DWINDOWS -DWIN32";
$app_cflag="-WC";
$lib_cflag="-WC";
$lflags.=" -Tpe";

if ($shlib)
	{
	$mlflags="$base_lflags -Tpe"; # stack if defined in .def file
	$libs="libw ldllcew";
	}
else
	{ $mlflags=''; }

$obj='.obj';
$ofile="-o";

# EXE linking stuff
$link="tlink32";
$efile="";
$exep='.exe';
$ex_libs="CW32.LIB IMPORT32.LIB";
$ex_libs.=$no_sock?"":" wsock32.lib";
$shlib_ex_obj="" if $shlib;
$app_ex_obj="C0X32.OBJ";

# static library stuff
$mklib='tlib';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='';

$asm='ml /Cp /c /Cx';
$afile='/Fo';
if ($noasm)
	{
	$bn_asm_obj='';
	$bn_asm_src='';
	}
else
	{
	$bn_asm_obj='crypto\bn\asm\x86b32.obj';
	$bn_asm_src='crypto\bn\asm\x86m32.asm';
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
		# $(SHLIB_EX_OBJ)
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
	local($target,$files,$dep_libs,$libs)=@_;
	local($ret,$f,$_,@f);
	
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	$ret.="  \$(LINK) @&&|";
	
	# Due to a pathetic line length limit, I have to unwrap the args.
	$r="  \$(LFLAGS) ";
	if ($files =~ /\(([^)]*)\)$/)
		{
		@a=('$(APP_EX_OBJ)');
		push(@a,sort split(/\s+/,$Vars{$1}));
		foreach $_ (@a)
			{
			$ret.="\n  $r $_ +";
			$r="";
			}
		chop($ret);
		$ret.="\n";
		}
	else
		{ $ret.="\n $r \$(APP_EX_OBJ) $files\n"; }
	$ret.="  $target\n\n  $libs\n\n|\n\n";
	return($ret);
	}

1;
