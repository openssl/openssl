#!/usr/local/bin/perl
# VC-32.pl - unified script for Microsoft Visual C++, covering Win32,
# Win64 and WinCE [follow $FLAVOR variable to trace the differences].
#

$ssl=	"ssleay32";
$crypto="libeay32";

$o='\\';
$cp='$(PERL) util/copy.pl';
$mkdir='$(PERL) util/mkdir-p.pl';
$rm='del';

$zlib_lib="zlib1.lib";

# C compiler stuff
$cc='cl';
if ($FLAVOR =~ /WIN64/)
    {
    # Note that we currently don't have /WX on Win64! There is a lot of
    # warnings, but only of two types:
    #
    # C4344: conversion from '__int64' to 'int/long', possible loss of data
    # C4267: conversion from 'size_t' to 'int/long', possible loss of data
    #
    # Amount of latter type is minimized by aliasing strlen to function of
    # own desing and limiting its return value to 2GB-1 (see e_os.h). As
    # per 0.9.8 release remaining warnings were explicitly examined and
    # considered safe to ignore.
    # 
    $base_cflags=' /W3 /Gs0 /GF /Gy /nologo -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -DOPENSSL_SYSNAME_WIN32 -DOPENSSL_SYSNAME_WINNT -DUNICODE -D_UNICODE';
    $base_cflags.=' -D_CRT_SECURE_NO_DEPRECATE';	# shut up VC8
    $base_cflags.=' -D_CRT_NONSTDC_NO_DEPRECATE';	# shut up VC8
    my $f = $shlib?' /MD':' /MT';
    $lib_cflag='/Zl' if (!$shlib);	# remove /DEFAULTLIBs from static lib
    $opt_cflags=$f.' /Ox';
    $dbg_cflags=$f.'d /Od -DDEBUG -D_DEBUG';
    $lflags="/nologo /subsystem:console /opt:ref";
    }
elsif ($FLAVOR =~ /CE/)
    {
    # sanity check
    die '%OSVERSION% is not defined'	if (!defined($ENV{'OSVERSION'}));
    die '%PLATFORM% is not defined'	if (!defined($ENV{'PLATFORM'}));
    die '%TARGETCPU% is not defined'	if (!defined($ENV{'TARGETCPU'}));

    #
    # Idea behind this is to mimic flags set by eVC++ IDE...
    #
    $wcevers = $ENV{'OSVERSION'};			# WCENNN
    die '%OSVERSION% value is insane'	if ($wcevers !~ /^WCE([1-9])([0-9]{2})$/);
    $wcecdefs = "-D_WIN32_WCE=$1$2 -DUNDER_CE=$1$2";	# -D_WIN32_WCE=NNN
    $wcelflag = "/subsystem:windowsce,$1.$2";		# ...,N.NN

    $wceplatf =  $ENV{'PLATFORM'};
    $wceplatf =~ tr/a-z0-9 /A-Z0-9_/d;
    $wcecdefs .= " -DWCE_PLATFORM_$wceplatf";

    $wcetgt = $ENV{'TARGETCPU'};	# just shorter name...
    SWITCH: for($wcetgt) {
	/^X86/		&& do {	$wcecdefs.=" -Dx86 -D_X86_ -D_i386_ -Di_386_";
				$wcelflag.=" /machine:IX86";	last; };
	/^ARMV4[IT]/	&& do { $wcecdefs.=" -DARM -D_ARM_ -D$wcetgt";
				$wcecdefs.=" -DTHUMB -D_THUMB_" if($wcetgt=~/T$/);
				$wcecdefs.=" -QRarch4T -QRinterwork-return";
				$wcelflag.=" /machine:THUMB";	last; };
	/^ARM/		&& do {	$wcecdefs.=" -DARM -D_ARM_ -D$wcetgt";
				$wcelflag.=" /machine:ARM";	last; };
	/^MIPSIV/	&& do {	$wcecdefs.=" -DMIPS -D_MIPS_ -DR4000 -D$wcetgt";
				$wcecdefs.=" -D_MIPS64 -QMmips4 -QMn32";
				$wcelflag.=" /machine:MIPSFPU";	last; };
	/^MIPS16/	&& do {	$wcecdefs.=" -DMIPS -D_MIPS_ -DR4000 -D$wcetgt";
				$wcecdefs.=" -DMIPSII -QMmips16";
				$wcelflag.=" /machine:MIPS16";	last; };
	/^MIPSII/	&& do {	$wcecdefs.=" -DMIPS -D_MIPS_ -DR4000 -D$wcetgt";
				$wcecdefs.=" -QMmips2";
				$wcelflag.=" /machine:MIPS";	last; };
	/^R4[0-9]{3}/	&& do {	$wcecdefs.=" -DMIPS -D_MIPS_ -DR4000";
				$wcelflag.=" /machine:MIPS";	last; };
	/^SH[0-9]/	&& do {	$wcecdefs.=" -D$wcetgt -D_$wcetgt_ -DSHx";
				$wcecdefs.=" -Qsh4" if ($wcetgt =~ /^SH4/);
				$wcelflag.=" /machine:$wcetgt";	last; };
	{ $wcecdefs.=" -D$wcetgt -D_$wcetgt_";
	  $wcelflag.=" /machine:$wcetgt";			last; };
    }

    $cc='$(CC)';
    $base_cflags=' /W3 /WX /GF /Gy /nologo -DUNICODE -D_UNICODE -DOPENSSL_SYSNAME_WINCE -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -DNO_CHMOD -I$(WCECOMPAT)/include -DOPENSSL_SMALL_FOOTPRINT';
    $base_cflags.=" $wcecdefs";
    $opt_cflags=' /MC /O1i';	# optimize for space, but with intrinsics...
    $dbg_clfags=' /MC /Od -DDEBUG -D_DEBUG';
    $lflags="/nologo /opt:ref $wcelflag";
    }
else	# Win32
    {
    $base_cflags=' /W3 /WX /Gs0 /GF /Gy /nologo -DOPENSSL_SYSNAME_WIN32 -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32';
    $base_cflags.=' -D_CRT_SECURE_NO_DEPRECATE';	# shut up VC8
    $base_cflags.=' -D_CRT_NONSTDC_NO_DEPRECATE';	# shut up VC8
    my $f = $shlib?' /MD':' /MT';
    $lib_cflag='/Zl' if (!$shlib);	# remove /DEFAULTLIBs from static lib
    $opt_cflags=$f.' /Ox /O2 /Ob2';
    $dbg_cflags=$f.'d /Od -DDEBUG -D_DEBUG';
    $lflags="/nologo /subsystem:console /opt:ref";
    }
$mlflags='';

$out_def="out32"; $out_def.='_$(TARGETCPU)' if ($FLAVOR =~ /CE/);
$tmp_def="tmp32"; $tmp_def.='_$(TARGETCPU)' if ($FLAVOR =~ /CE/);
$inc_def="inc32";

if ($debug)
	{
	$cflags=$dbg_cflags.$base_cflags;
	$lflags.=" /debug";
	$mlflags.=' /debug';
	}
else
	{
	$cflags=$opt_cflags.$base_cflags;
	}

$obj='.obj';
$ofile="/Fo";

# EXE linking stuff
$link="link";
$rsc="rc";
$efile="/out:";
$exep='.exe';
if ($no_sock)		{ $ex_libs=''; }
elsif ($FLAVOR =~ /CE/)	{ $ex_libs='winsock.lib'; }
else			{ $ex_libs='wsock32.lib'; }

if ($FLAVOR =~ /CE/)
	{
	$ex_libs.=' $(WCECOMPAT)/lib/wcecompatex.lib';
	$ex_libs.=' /nodefaultlib:oldnames.lib coredll.lib corelibc.lib' if ($ENV{'TARGETCPU'} eq "X86");
	}
else
	{
	$ex_libs.=' gdi32.lib advapi32.lib user32.lib';
	$ex_libs.=' bufferoverflowu.lib' if ($FLAVOR =~ /WIN64/);
	}

# As native NT API is pure UNICODE, our WIN-NT build defaults to UNICODE,
# but gets linked with unicows.lib to ensure backward compatibility.
if ($FLAVOR =~ /NT/)
	{
	$cflags.=" -DOPENSSL_SYSNAME_WINNT -DUNICODE -D_UNICODE";
	$ex_libs="unicows.lib $ex_libs";
	}
# static library stuff
$mklib='lib';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='/out:';

$shlib_ex_obj="";
$app_ex_obj="setargv.obj" if ($FLAVOR !~ /CE/);
if ($nasm) {
	my $ver=`nasm -v 2>NUL`;
	my $vew=`nasmw -v 2>NUL`;
	# pick newest version
	$asm=($ver gt $vew?"nasm":"nasmw")." -f win32";
	$afile='-o ';
} else {
	$asm='ml /Cp /coff /c /Cx';
	$asm.=" /Zi" if $debug;
	$afile='/Fo';
}

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm)
	{
	$aes_asm_obj='crypto\aes\asm\a_win32.obj';
	$aes_asm_src='crypto\aes\asm\a_win32.asm';
	$bn_asm_obj='crypto\bn\asm\bn_win32.obj';
	$bn_asm_src='crypto\bn\asm\bn_win32.asm';
	$bnco_asm_obj='crypto\bn\asm\co_win32.obj';
	$bnco_asm_src='crypto\bn\asm\co_win32.asm';
	$des_enc_obj='crypto\des\asm\d_win32.obj crypto\des\asm\y_win32.obj';
	$des_enc_src='crypto\des\asm\d_win32.asm crypto\des\asm\y_win32.asm';
	$bf_enc_obj='crypto\bf\asm\b_win32.obj';
	$bf_enc_src='crypto\bf\asm\b_win32.asm';
	$cast_enc_obj='crypto\cast\asm\c_win32.obj';
	$cast_enc_src='crypto\cast\asm\c_win32.asm';
	$rc4_enc_obj='crypto\rc4\asm\r4_win32.obj';
	$rc4_enc_src='crypto\rc4\asm\r4_win32.asm';
	$rc5_enc_obj='crypto\rc5\asm\r5_win32.obj';
	$rc5_enc_src='crypto\rc5\asm\r5_win32.asm';
	$md5_asm_obj='crypto\md5\asm\m5_win32.obj';
	$md5_asm_src='crypto\md5\asm\m5_win32.asm';
	$sha1_asm_obj='crypto\sha\asm\s1_win32.obj crypto\sha\asm\sha512-sse2.obj';
	$sha1_asm_src='crypto\sha\asm\s1_win32.asm crypto\sha\asm\sha512-sse2.asm';
	$rmd160_asm_obj='crypto\ripemd\asm\rm_win32.obj';
	$rmd160_asm_src='crypto\ripemd\asm\rm_win32.asm';
	$cpuid_asm_obj='crypto\cpu_win32.obj';
	$cpuid_asm_src='crypto\cpu_win32.asm';
	$cflags.=" -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DAES_ASM -DBN_ASM -DOPENSSL_BN_ASM_PART_WORDS -DMD5_ASM -DSHA1_ASM -DRMD160_ASM";
	}

if ($shlib && $FLAVOR !~ /CE/)
	{
	$mlflags.=" $lflags /dll";
	$lib_cflag=" -D_WINDLL";
	$out_def="out32dll";
	$tmp_def="tmp32dll";
	#
	# Engage Applink...
	#
	$app_ex_obj.=" \$(OBJ_D)\\applink.obj /implib:\$(TMP_D)\\junk.lib";
	$cflags.=" -DOPENSSL_USE_APPLINK -I.";
	# I'm open for better suggestions than overriding $banner...
	$banner=<<'___';
	@echo Building OpenSSL

$(OBJ_D)\applink.obj:	ms\applink.c
	$(CC) /Fo$(OBJ_D)\applink.obj $(APP_CFLAGS) -c ms\applink.c
$(OBJ_D)\uplink.obj:	ms\uplink.c ms\applink.c
	$(CC) /Fo$(OBJ_D)\uplink.obj $(SHLIB_CFLAGS) -c ms\uplink.c
$(INCO_D)\applink.c:	ms\applink.c
	$(CP) ms\applink.c $(INCO_D)\applink.c

EXHEADER= $(EXHEADER) $(INCO_D)\applink.c

LIBS_DEP=$(LIBS_DEP) $(OBJ_D)\applink.obj
CRYPTOOBJ=$(OBJ_D)\uplink.obj $(CRYPTOOBJ)
___
	$banner.=<<'___' if ($FLAVOR =~ /WIN64/);
CRYPTOOBJ=ms\uptable.obj $(CRYPTOOBJ)
___
	}
elsif ($shlib && $FLAVOR =~ /CE/)
	{
	$mlflags.=" $lflags /dll";
	$lib_cflag=" -D_WINDLL -D_DLL";
	$out_def='out32dll_$(TARGETCPU)';
	$tmp_def='tmp32dll_$(TARGETCPU)';
	}

$cflags.=" /Fd$out_def";

sub do_lib_rule
	{
	local($objs,$target,$name,$shlib)=@_;
	local($ret);

	$taget =~ s/\//$o/g if $o ne '/';
	if ($name ne "")
		{
		$name =~ tr/a-z/A-Z/;
		$name = "/def:ms/${name}.def";
		}

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
		local($ex)=($target =~ /O_CRYPTO/)?'':' $(L_CRYPTO)';
		if ($name eq "")
			{
			$ex.=' bufferoverflowu.lib' if ($FLAVOR =~ /WIN64/);
			}
		elsif ($FLAVOR =~ /CE/)
			{
			$ex.=' winsock.lib $(WCECOMPAT)/lib/wcecompatex.lib';
			}
		else
			{
			$ex.=' unicows.lib' if ($FLAVOR =~ /NT/);
			$ex.=' wsock32.lib gdi32.lib advapi32.lib user32.lib';
			$ex.=' bufferoverflowu.lib' if ($FLAVOR =~ /WIN64/);
			}
		$ex.=" $zlib_lib" if $zlib_opt == 1 && $target =~ /O_CRYPTO/;
		$ret.="\t\$(LINK) \$(MLFLAGS) $efile$target $name @<<\n  \$(SHLIB_EX_OBJ) $objs $ex\n<<\n";
        $ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;2\n\n";
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
	$ret.="\t\$(LINK) \$(LFLAGS) $efile$target @<<\n";
	$ret.="  \$(APP_EX_OBJ) $files $libs\n<<\n";
    $ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;1\n\n";
	return($ret);
	}

1;
