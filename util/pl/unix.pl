#!/usr/local/bin/perl
#
# unix.pl - the standard unix makefile stuff.
#

$o='/';
$cp='/bin/cp';
$rm='/bin/rm -f';

# C compiler stuff

if ($gcc)
	{
	$cc='gcc';
	if ($debug)
		{ $cflags="-g2 -ggdb"; }
	else
		{ $cflags="-O3 -fomit-frame-pointer"; }
	}
else
	{
	$cc='cc';
	if ($debug)
		{ $cflags="-g"; }
	else
		{ $cflags="-O"; }
	}
$obj='.o';
$asm_suffix='.s';
$ofile='-o ';

# EXE linking stuff
$link='${CC}';
$lflags='${CFLAG}';
$efile='-o ';
$exep='';
$ex_libs="";

# static library stuff
$mklib='ar r';
$mlflags='';
$ranlib=&which("ranlib") or $ranlib="true";
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

%perl1 = (
	  'md5-x86_64' => 'crypto/md5',
	  'x86_64-mont' => 'crypto/bn',
	  'x86_64-mont5' => 'crypto/bn',
	  'x86_64-gf2m' => 'crypto/bn',
	  'aes-x86_64' => 'crypto/aes',
	  'vpaes-x86_64' => 'crypto/aes',
	  'bsaes-x86_64' => 'crypto/aes',
	  'aesni-x86_64' => 'crypto/aes',
	  'aesni-sha1-x86_64' => 'crypto/aes',
	  'sha1-x86_64' => 'crypto/sha',
	  'e_padlock-x86_64' => 'engines',
	  'rc4-x86_64' => 'crypto/rc4',
	  'rc4-md5-x86_64' => 'crypto/rc4',
	  'ghash-x86_64' => 'crypto/modes',
	  'aesni-gcm-x86_64' => 'crypto/modes',
	  'aesni-sha256-x86_64' => 'crypto/aes',
          'rsaz-x86_64' => 'crypto/bn',
          'rsaz-avx2' => 'crypto/bn',
	  'aesni-mb-x86_64' => 'crypto/aes',
	  'sha1-mb-x86_64' => 'crypto/sha',
	  'sha256-mb-x86_64' => 'crypto/sha',
	  'ecp_nistz256-x86_64' => 'crypto/ec',
	  'wp-x86_64' => 'crypto/whrlpool',
	  'cmll-x86_64' => 'crypto/camellia',
         );

# If I were feeling more clever, these could probably be extracted
# from makefiles.
sub platform_perlasm_compile_target
	{
	local($target, $source, $bname) = @_;

	for $p (keys %perl1)
	        {
# FIXME: export CC so rsaz-avx2 can test for it, since BSD make does
# not export variables, unlike GNU make. But this also requires fixing
# the .s.o rule to use CC!
		if ($target eq "\$(OBJ_D)/$p.o")
		        {
			return << "EOF";
\$(TMP_D)/$p.s: $perl1{$p}/asm/$p.pl
	\$(PERL) $perl1{$p}/asm/$p.pl \$(PERLASM_SCHEME) > \$@
EOF
		        }
	        }
	if ($target eq '$(OBJ_D)/x86_64cpuid.o')
		{
		return << 'EOF';
$(TMP_D)/x86_64cpuid.s: crypto/x86_64cpuid.pl
	$(PERL) crypto/x86_64cpuid.pl $(PERLASM_SCHEME) > $@
EOF
		}
	elsif ($target eq '$(OBJ_D)/sha256-x86_64.o')
		{
		return << 'EOF';
$(TMP_D)/sha256-x86_64.s: crypto/sha/asm/sha512-x86_64.pl
	$(PERL) crypto/sha/asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
EOF
	        }
	elsif ($target eq '$(OBJ_D)/sha512-x86_64.o')
		{
		return << 'EOF';
$(TMP_D)/sha512-x86_64.s: crypto/sha/asm/sha512-x86_64.pl
	$(PERL) crypto/sha/asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
EOF
	        }
	elsif ($target eq '$(OBJ_D)/sha512-x86_64.o')
		{
		return << 'EOF';
$(TMP_D)/sha512-x86_64.s: crypto/sha/asm/sha512-x86_64.pl
	$(PERL) crypto/sha/asm/sha512-x86_64.pl $(PERLASM_SCHEME) $@
EOF
	        }

	die $target;
	}

sub special_compile_target
	{
	local($target) = @_;

	if ($target eq 'crypto/bn/x86_64-gcc')
		{
		return << "EOF";
\$(TMP_D)/x86_64-gcc.o:	crypto/bn/asm/x86_64-gcc.c
	\$(CC) \$(LIB_CFLAGS) -c -o \$@ crypto/bn/asm/x86_64-gcc.c
EOF
		}
	return undef;
	}

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

sub which
	{
	my ($name)=@_;
	my $path;
	foreach $path (split /:/, $ENV{PATH})
		{
		if (-x "$path/$name")
			{
			return "$path/$name";
			}
		}
	}

sub do_rehash_rule {
    my ($target, $deps) = @_;
    my $ret = <<"EOF";
$target: $deps
	(OPENSSL="`pwd`/util/opensslwrap.sh"; \\
	OPENSSL_DEBUG_MEMORY=on; \\
	export OPENSSL OPENSSL_DEBUG_MEMORY; \\
	\$(PERL) tools/c_rehash certs/demo; \\
	touch $target)
EOF
    return $ret
}
sub do_test_rule {
    my ($target, $deps, $test_cmd) = @_;
    my $ret = <<"EOF";
$target: $deps force.$target
	TOP=. BIN_D=\$(BIN_D) TEST_D=\$(TEST_D) \\
	    PERL=\$(PERL) \$(PERL) test/$test_cmd
force.$target:

EOF
    return $ret;
}


1;
