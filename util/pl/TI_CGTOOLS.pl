#!/usr/local/bin/perl
#
# TI_CGTOOLS.pl, Texas Instruments CGTOOLS under Unix or MSYS.
#

$ssl=	"ssl";
$crypto="crypto";

if ($fips && !$shlib)
	{
	$crypto="fips";
	$crypto_compat = "cryptocompat.lib";
	}
else
	{
	$crypto="crypto";
	}

if ($fipscanisterbuild)
	{
	$fips_canister_path = "\$(LIB_D)/fipscanister.obj";
	}

$o='/';
$cp='cp';
$cp2='$(PERL) util/copy.pl -stripcr';
$mkdir='$(PERL) util/mkdir-p.pl';
$rm='rm -f';

$zlib_lib="zlib1.lib";

# Santize -L options for ms link
$l_flags =~ s/-L("\[^"]+")/\/libpath:$1/g;
$l_flags =~ s/-L(\S+)/\/libpath:$1/g;

# C compiler stuff
$cc='cl6x';
$base_cflags= " $mf_cflag";
my $f;
$opt_cflags='';
$dbg_cflags=$f.' -g -DDEBUG -D_DEBUG';
$lflags='';

*::cc_compile_target = sub {
	my ($target,$source,$ex_flags)=@_;
	my $ret;

	$ex_flags.=" -DMK1MF_BUILD" if ($source =~/cversion/);
	$ret ="$target: \$(SRC_D)$o$source\n\t";
	if ($fipscanisterbuild && $source=~/\.asm$/) {
		$ret.="\$(PERL) util${o}fipsas.pl . \$< norunasm \$(CFLAG)\n\t";
	}
	$ret.="\$(CC) --obj_directory=\$(OBJ_D) $ex_flags -c \$(SRC_D)$o$source\n";
	$target =~ s/.*${o}([^${o}]+)/$1/;
	$source =~ s/.*${o}([^${o}\.]+)\..*/$1${obj}/;
	$ret.="\tmv \$(OBJ_D)${o}$source \$(OBJ_D)${o}$target\n" if ($target ne $source);
	$ret.="\n";
	return($ret);
};
*::perlasm_compile_target = sub {
	my ($target,$source,$bname)=@_;
	my $ret;

	$bname =~ s/(.*)\.[^\.]$/$1/;
	$ret=<<___;
\$(TMP_D)$o$bname.asm: $source
	\$(PERL) $source \$\@
___
	$ret .= "\t\$(PERL) util${o}fipsas.pl . \$@ norunasm \$(CFLAG)\n" if $fipscanisterbuild;

	$ret.=<<___;

$target: \$(TMP_D)$o$bname.asm
	\$(ASM) --obj_directory=\$(OBJ_D) \$(TMP_D)$o$bname.asm

___
};

$mlflags='';

$out_def ="c6x";
$tmp_def ="$out_def/tmp";
$inc_def="$out_def/inc";

if ($debug)
	{
	$cflags=$dbg_cflags.$base_cflags;
	}
else
	{
	$cflags=$opt_cflags.$base_cflags;
	}

$obj='.obj';
$asm_suffix='.asm';
$ofile="";

# EXE linking stuff
$link='$(CC) -z';
$efile="-o ";
$exep='.out';
$ex_libs='';

# static library stuff
$mklib='ar6x';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='-o ';

$shlib_ex_obj="";
$asm='$(CC) $(CFLAG) -c';

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm)
	{
	import_asm($mf_bn_asm, "bn", \$bn_asm_obj, \$bn_asm_src);
	import_asm($mf_aes_asm, "aes", \$aes_asm_obj, \$aes_asm_src);
	import_asm($mf_des_asm, "des", \$des_enc_obj, \$des_enc_src);
	import_asm($mf_bf_asm, "bf", \$bf_enc_obj, \$bf_enc_src);
	import_asm($mf_cast_asm, "cast", \$cast_enc_obj, \$cast_enc_src);
	import_asm($mf_rc4_asm, "rc4", \$rc4_enc_obj, \$rc4_enc_src);
	import_asm($mf_rc5_asm, "rc5", \$rc5_enc_obj, \$rc5_enc_src);
	import_asm($mf_md5_asm, "md5", \$md5_asm_obj, \$md5_asm_src);
	import_asm($mf_sha_asm, "sha", \$sha1_asm_obj, \$sha1_asm_src);
	import_asm($mf_rmd_asm, "ripemd", \$rmd160_asm_obj, \$rmd160_asm_src);
	import_asm($mf_wp_asm, "whrlpool", \$whirlpool_asm_obj, \$whirlpool_asm_src);
	import_asm($mf_modes_asm, "modes", \$modes_asm_obj, \$modes_asm_src);
	import_asm($mf_cpuid_asm, "", \$cpuid_asm_obj, \$cpuid_asm_src);
	$perl_asm = 1;
	}

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
	if ($name ne "")
		{
		$name =~ tr/a-z/A-Z/;
		$name = "/def:ms/${name}.def";
		}

#	$target="\$(LIB_D)$o$target";
#	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ret.="$target: $objs\n";
		$ret.="\t\$(MKLIB) $lfile$target $objs\n";
		}
	else
		{
		local($ex)=($target =~ /O_CRYPTO/)?'':' $(L_CRYPTO)';
		$ex.=" $zlib_lib" if $zlib_opt == 1 && $target =~ /O_CRYPTO/;

 		if ($fips && $target =~ /O_CRYPTO/)
			{
			$ret.="$target: $objs \$(PREMAIN_DSO_EXE)";
			$ret.="\n\tFIPS_LINK=\"\$(LINK)\" \\\n";
			$ret.="\tFIPS_CC=\$(CC)\\\n";
			$ret.="\tFIPS_CC_ARGS=/Fo\$(OBJ_D)${o}fips_premain.obj \$(SHLIB_CFLAGS) -c\\\n";
			$ret.="\tPREMAIN_DSO_EXE=\$(PREMAIN_DSO_EXE)\\\n";
			$ret.="\tFIPS_SHA1_EXE=\$(FIPS_SHA1_EXE)\\\n";
			$ret.="\tFIPS_TARGET=$target\\\n";
			$ret.="\tFIPSLIB_D=\$(FIPSLIB_D)\\\n";
			$ret.="\t\$(FIPSLINK) \$(MLFLAGS) /map $base_arg $efile$target ";
			$ret.="$name \$(SHLIB_EX_OBJ) $objs \$(EX_LIBS) ";
			$ret.="\$(OBJ_D)${o}fips_premain.obj $ex\n";
			}
		else
			{
			$ret.="$target: $objs";
			$ret.="\n\t\$(LINK) \$(MLFLAGS) $efile$target $name \$(SHLIB_EX_OBJ) $objs $ex \$(EX_LIBS)\n";
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
		$ret.="	\$(LINK) \$(LFLAGS) $efile$target ";
		$ret.= "\$(EX_LIBS) " if ($files =~ /O_FIPSCANISTER/ && !$fipscanisterbuild);
		$ret.="$files $libs\n";
		}
	elsif ($standalone == 2)
		{
		$ret.="\t\$(LINK) \$(LFLAGS) $efile$target $files \$(O_FIPSCANISTER) $out_def/application.cmd\n";
		$ret.="\t$out_def/incore6x $target\n\n";
		}
	else
		{
		$ret.="\t\$(LINK) \$(LFLAGS) $efile$target ";
		$ret.="\t\$(APP_EX_OBJ) $files $libs\n";
		}
	return($ret);
	}

sub do_rlink_rule
	{
	local($target,$rl_start, $rl_mid, $rl_end,$dep_libs,$libs)=@_;
	local($ret,$_);
	my $files = "$rl_start $rl_mid $rl_end";

	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($target);
	$ret.="$target: $files $dep_libs\n";
	$ret.="\t\$(LINK) -r $lfile$target $files $out_def/fipscanister.cmd\n";
	$ret.="\t\$(PERL) $out_def${o}fips_standalone_sha1 $target > ${target}.sha1\n";
	$ret.="\t\$(PERL) util${o}copy.pl -stripcr fips${o}fips_premain.c \$(LIB_D)${o}fips_premain.c\n";
	$ret.="\t\$(CP) fips${o}fips_premain.c.sha1 \$(LIB_D)${o}fips_premain.c.sha1\n";
	$ret.="\n";
	return($ret);
	}

sub import_asm
	{
	my ($mf_var, $asm_name, $oref, $sref) = @_;
	my $asm_dir;
	if ($asm_name eq "")
		{
		$asm_dir = "crypto$o";
		}
	else
		{
		$asm_dir = "crypto$o$asm_name$oasm$o";
		}

	$$oref = "";
	$$sref = "";
	$mf_var =~ s/\.o//g;

	foreach (split(/ /, $mf_var))
		{
		$$sref .= $asm_dir . $_ . ".asm ";
		}
	foreach (split(/ /, $mf_var))
		{
		$$oref .= "\$(TMP_D)\\" . $_ . ".obj ";
		}
	$$oref =~ s/ $//;
	$$sref =~ s/ $//;

	}


1;
