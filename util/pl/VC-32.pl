#!/usr/local/bin/perl
# VC-32.pl - unified script for Microsoft Visual C++, covering Win32,
# Win64 and WinCE [follow $FLAVOR variable to trace the differences].
#

$ssl=	"ssleay32";

if ($fips && !$shlib)
	{
	$crypto="libeayfips32";
	$crypto_compat = "libeaycompat32.lib";
	}
else
	{
	$crypto="libeay32";
	}

if ($fipscanisterbuild)
	{
	$fips_canister_path = "\$(LIB_D)\\fipscanister.lib";
	}

$o='\\';
$cp='$(PERL) util/copy.pl';
$mkdir='$(PERL) util/mkdir-p.pl';
$rm='del /Q';

$zlib_lib="zlib1.lib";

# Santize -L options for ms link
$l_flags =~ s/-L("\[^"]+")/\/libpath:$1/g;
$l_flags =~ s/-L(\S+)/\/libpath:$1/g;

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
    my $f = $shlib || $fips ?' /MD':' /MT';
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
    my $f = $shlib || $fips ?' /MD':' /MT';
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
	$cflags=$dbg_cflags.$base_cflags.' /Zi';
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

my $oflow;


if ($FLAVOR =~ /WIN64/ and `cl 2>&1` =~ /14\.00\.4[0-9]{4}\./)
	{
	$oflow=' bufferoverflowu.lib';
	}
else
	{
	$oflow="";
	}

if ($FLAVOR =~ /CE/)
	{
	$ex_libs.=' $(WCECOMPAT)/lib/wcecompatex.lib';
	$ex_libs.=' /nodefaultlib:oldnames.lib coredll.lib corelibc.lib' if ($ENV{'TARGETCPU'} eq "X86");
	}
else
	{
	$ex_libs.=' gdi32.lib crypt32.lib advapi32.lib user32.lib';
	$ex_libs.= $oflow;

	}

# As native NT API is pure UNICODE, our WIN-NT build defaults to UNICODE,
# but gets linked with unicows.lib to ensure backward compatibility.
if ($FLAVOR =~ /NT/)
	{
	$cflags.=" -DOPENSSL_SYSNAME_WINNT -DUNICODE -D_UNICODE";
	$ex_libs="unicows.lib $ex_libs";
	}
# static library stuff
$mklib='lib /nologo';
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
} elsif ($ml64) {
	$asm='ml64 /c /Cp /Cx';
	$asm.=' /Zi' if $debug;
	$afile='/Fo';
} else {
	$asm='ml /nologo /Cp /coff /c /Cx';
	$asm.=" /Zi" if $debug;
	$afile='/Fo';
}

$aes_asm_obj='';
$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm)
    {
    if ($FLAVOR =~ "WIN32")
	{
	$aes_asm_obj='crypto\aes\asm\a_win32.obj';
	$aes_asm_src='crypto\aes\asm\a_win32.asm';
	$bn_asm_obj='crypto\bn\asm\bn_win32.obj crypto\bn\asm\mt_win32.obj';
	$bn_asm_src='crypto\bn\asm\bn_win32.asm crypto\bn\asm\mt_win32.asm';
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
	$cflags.=" -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DAES_ASM -DBN_ASM -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_BN_ASM_MONT -DMD5_ASM -DSHA1_ASM -DRMD160_ASM";
	}
    elsif ($FLAVOR =~ "WIN64A")
	{
	$aes_asm_obj='$(OBJ_D)\aes-x86_64.obj';
	$aes_asm_src='crypto\aes\asm\aes-x86_64.asm';
	$bn_asm_obj='$(OBJ_D)\x86_64-mont.obj $(OBJ_D)\bn_asm.obj';
	$bn_asm_src='crypto\bn\asm\x86_64-mont.asm';
	$sha1_asm_obj='$(OBJ_D)\sha1-x86_64.obj $(OBJ_D)\sha256-x86_64.obj $(OBJ_D)\sha512-x86_64.obj';
	$sha1_asm_src='crypto\sha\asm\sha1-x86_64.asm crypto\sha\asm\sha256-x86_64.asm crypto\sha\asm\sha512-x86_64.asm';
	$cpuid_asm_obj='$(OBJ_D)\cpuid-x86_64.obj';
	$cpuid_asm_src='crypto\cpuid-x86_64.asm';
	$cflags.=" -DOPENSSL_CPUID_OBJ -DAES_ASM -DOPENSSL_BN_ASM_MONT -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM";
	}
    }

if ($shlib && $FLAVOR !~ /CE/)
	{
	$mlflags.=" $lflags /dll";
#	$cflags =~ s| /MD| /MT|;
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
___
$banner .= "CRYPTOOBJ=\$(OBJ_D)\\uplink.obj \$(CRYPTOOBJ)\n";
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
	my($objs,$target,$name,$shlib,$ign,$base_addr) = @_;
	local($ret);

	$taget =~ s/\//$o/g if $o ne '/';
	my $base_arg;
	if ($base_addr ne "")
		{
		$base_arg= " /base:$base_addr";
		}
	else
		{
		$base_arg = "";
		}
	if ($target =~ /O_CRYPTO/ && $fipsdso)
		{
		$name = "/def:ms/libeayfips.def";
		}
	elsif ($name ne "")
		{
		$name =~ tr/a-z/A-Z/;
		$name = "/def:ms/${name}.def";
		}

#	$target="\$(LIB_D)$o$target";
#	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ex =' ';
		$ret.="$target: $objs\n";
		$ret.="\t\$(MKLIB) $lfile$target @<<\n  $objs $ex\n<<\n";
		}
	else
		{
		my $ex = "";		
		if ($target =~ /O_SSL/)
			{
			$ex .= " \$(L_CRYPTO)";
			#$ex .= " \$(L_FIPS)" if $fipsdso;
			}
		my $fipstarget;
		if ($fipsdso)
			{
			$fipstarget = "O_FIPS";
			}
		else
			{
			$fipstarget = "O_CRYPTO";
			}


		if ($name eq "")
			{
			$ex.= $oflow;
			if ($target =~ /capi/)
				{
				$ex.=' crypt32.lib advapi32.lib';
				}
			}
		elsif ($FLAVOR =~ /CE/)
			{
			$ex.=' winsock.lib $(WCECOMPAT)/lib/wcecompatex.lib';
			}
		else
			{
			$ex.=' unicows.lib' if ($FLAVOR =~ /NT/);
			$ex.=' wsock32.lib gdi32.lib advapi32.lib user32.lib';
			$ex.=' crypt32.lib';
			$ex.= $oflow;
			}
		$ex.=" $zlib_lib" if $zlib_opt == 1 && $target =~ /O_CRYPTO/;

 		if ($fips && $target =~ /$fipstarget/)
			{
			$ex.= $mwex unless $fipscanisterbuild;
			$ret.="$target: $objs \$(PREMAIN_DSO_EXE)";
			if ($fipsdso)
				{
				$ex.=" \$(OBJ_D)\\\$(LIBFIPS).res";
				$ret.=" \$(OBJ_D)\\\$(LIBFIPS).res";
				$ret.=" ms/\$(LIBFIPS).def";
				}
			$ret.="\n\tSET FIPS_LINK=\$(LINK)\n";
			$ret.="\tSET FIPS_CC=\$(CC)\n";
			$ret.="\tSET FIPS_CC_ARGS=/Fo\$(OBJ_D)${o}fips_premain.obj \$(SHLIB_CFLAGS) -c\n";
			$ret.="\tSET PREMAIN_DSO_EXE=\$(PREMAIN_DSO_EXE)\n";
			$ret.="\tSET FIPS_SHA1_EXE=\$(FIPS_SHA1_EXE)\n";
			$ret.="\tSET FIPS_TARGET=$target\n";
			$ret.="\tSET FIPSLIB_D=\$(FIPSLIB_D)\n";
			$ret.="\t\$(FIPSLINK) \$(MLFLAGS) /fixed /map $base_arg $efile$target ";
			$ret.="$name @<<\n  \$(SHLIB_EX_OBJ) $objs ";
			$ret.="\$(OBJ_D)${o}fips_premain.obj $ex\n<<\n";
			}
		else
			{
			$ret.="$target: $objs";
			if ($target =~ /O_CRYPTO/ && $fipsdso)
				{
				$ret .= " \$(O_FIPS)";
				$ex .= " \$(L_FIPS)";
				}
			$ret.="\n\t\$(LINK) \$(MLFLAGS) $efile$target $name @<<\n  \$(SHLIB_EX_OBJ) $objs $ex\n<<\n";
			}

        $ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;2\n\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	my($target,$files,$dep_libs,$libs,$standalone)=@_;
	local($ret,$_);
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	if ($standalone == 1)
		{
		$ret.="  \$(LINK) \$(LFLAGS) $efile$target @<<\n\t";
		$ret.= "\$(EX_LIBS) " if ($files =~ /O_FIPSCANISTER/ && !$fipscanisterbuild);
		$ret.="$files $libs\n<<\n";
		}
	elsif ($standalone == 2)
		{
		$ret.="\tSET FIPS_LINK=\$(LINK)\n";
		$ret.="\tSET FIPS_CC=\$(CC)\n";
		$ret.="\tSET FIPS_CC_ARGS=/Fo\$(OBJ_D)${o}fips_premain.obj \$(SHLIB_CFLAGS) -c\n";
		$ret.="\tSET PREMAIN_DSO_EXE=\n";
		$ret.="\tSET FIPS_TARGET=$target\n";
		$ret.="\tSET FIPS_SHA1_EXE=\$(FIPS_SHA1_EXE)\n";
		$ret.="\tSET FIPSLIB_D=\$(FIPSLIB_D)\n";
		$ret.="\t\$(FIPSLINK) \$(LFLAGS) /fixed /map $efile$target @<<\n";
		$ret.="\t\$(APP_EX_OBJ) $files \$(OBJ_D)${o}fips_premain.obj $libs\n<<\n";
		}
	else
		{
		$ret.="\t\$(LINK) \$(LFLAGS) $efile$target @<<\n";
		$ret.="\t\$(APP_EX_OBJ) $files $libs\n<<\n";
		}
    	$ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;1\n\n";
	return($ret);
	}

sub do_rlink_rule
	{
	local($target,$rl_start, $rl_mid, $rl_end,$dep_libs,$libs)=@_;
	local($ret,$_);
	my $files = "$rl_start $rl_mid $rl_end";

	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs \$(FIPS_SHA1_EXE)\n";
	$ret.="\t\$(PERL) ms\\segrenam.pl \$\$a $rl_start\n";
	$ret.="\t\$(PERL) ms\\segrenam.pl \$\$b $rl_mid\n";
	$ret.="\t\$(PERL) ms\\segrenam.pl \$\$c $rl_end\n";
	$ret.="\t\$(MKLIB) $lfile$target @<<\n\t$files\n<<\n";
	$ret.="\t\$(FIPS_SHA1_EXE) $target > ${target}.sha1\n";
	$ret.="\t\$(PERL) util${o}copy.pl -stripcr fips${o}fips_premain.c \$(LIB_D)${o}fips_premain.c\n";
	$ret.="\t\$(CP) fips${o}fips_premain.c.sha1 \$(LIB_D)${o}fips_premain.c.sha1\n";
	$ret.="\n";
	return($ret);
	}

sub do_sdef_rule
	{
	my $ret = "ms/\$(LIBFIPS).def: \$(O_FIPSCANISTER)\n";
	$ret.="\t\$(PERL) util/mksdef.pl \$(MLFLAGS) /out:dummy.dll /def:ms/libeay32.def @<<\n  \$(O_FIPSCANISTER)\n<<\n";
	$ret.="\n";
	return $ret;
	}

1;
