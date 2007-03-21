# Metrowerks Codewarrior for NetWare
#

# The import files and other misc imports needed to link
@misc_imports = ("GetProcessSwitchCount", "RunningProcess",  
                 "GetSuperHighResolutionTimer");
if ($LIBC)
{
   @import_files = ("libc.imp");
   @module_files = ("libc");
}
else
{
   # clib build
   @import_files = ("clib.imp");
   @module_files = ("clib");
   push(@misc_imports, "_rt_modu64%16", "_rt_divu64%16");
}
if (!$BSDSOCK)
{
   push(@import_files, "ws2nlm.imp");
}
		 

# The "IMPORTS" environment variable must be set and point to the location
# where import files (*.imp) can be found.
# Example:  set IMPORTS=c:\ndk\nwsdk\imports
$import_path = $ENV{"IMPORTS"} || die ("IMPORTS environment variable not set\n");


# The "PRELUDE" environment variable must be set and point to the location
# and name of the prelude source to link with ( nwpre.obj is recommended ).
# Example: set PRELUDE=c:\codewar\novell support\metrowerks support\libraries\runtime\nwpre.obj
$prelude = $ENV{"PRELUDE"} || die ("PRELUDE environment variable not set\n");

#$ssl=   "ssleay32";
#$crypto="libeay32";

$o='\\\\';
$cp='copy >nul:';
$rm='del';

# C compiler
$cc="mwccnlm";

# Linker
$link="mwldnlm";

# librarian
$mklib="mwldnlm";

# assembler 
if ($nw_nasm) 
{
   $asm="nasmw -s -f coff";
   $afile="-o ";
   $asm.=" -g" if $debug;
}
elsif ($nw_mwasm) 
{
   $asm="mwasmnlm -maxerrors 20";
   $afile="-o ";
   $asm.=" -g" if $debug;
}
elsif ($nw_masm)
{
# masm assembly settings - it should be possible to use masm but haven't 
# got it working.
# $asm='ml /Cp /coff /c /Cx';
# $asm.=" /Zi" if $debug;
# $afile='/Fo';
   die("Support for masm assembler not yet functional\n");
}
else 
{
   $asm="";
   $afile="";
}



# compile flags
#
# NOTES: Several c files in the crypto subdirectory include headers from
#        their local directories.  Metrowerks wouldn't find these h files
#        without adding individual include directives as compile flags
#        or modifying the c files.  Instead of adding individual include
#        paths for each subdirectory a recursive include directive
#        is used ( -ir crypto ).
#
#        A similar issue exists for the engines and apps subdirectories.
#
#        Turned off the "possible" warnings ( -w nopossible ).  Metrowerks
#        complained a lot about various stuff.  May want to turn back
#        on for further development.
$cflags="-ir crypto -ir engines -ir apps -msgstyle gcc -align 4 -processor pentium \\
         -char unsigned -w on -w nolargeargs -w nopossible -w nounusedarg \\
         -w noimplicitconv -relax_pointers -nosyspath -DL_ENDIAN \\
         -DOPENSSL_SYSNAME_NETWARE -U_WIN32 -maxerrors 20 ";

# link flags
$lflags="-msgstyle gcc -zerobss -stacksize 32768 -nostdlib -sym internal ";


# additional flags based upon debug | non-debug
if ($debug)
{
   $cflags.=" -opt off -g -sym internal -DDEBUG";
}
else
{
# CodeWarrior compiler has a problem with optimizations for floating
# points - no optimizations until further investigation
#   $cflags.=" -opt all";
}

# If LibC build add in NKS_LIBC define and set the entry/exit
# routines - The default entry/exit routines are for CLib and don't exist
# in LibC
if ($LIBC)
{
   $cflags.=" -DNETWARE_LIBC";
   $lflags.=" -entry _LibCPrelude -exit _LibCPostlude -flags pseudopreemption";
}
else
{
   $cflags.=" -DNETWARE_CLIB";
   $lflags.=" -entry _Prelude -exit _Stop";
}

# If BSD Socket support is requested, set a define for the compiler
if ($BSDSOCK)
{
   $cflags.=" -DNETWARE_BSDSOCK";
}


# linking stuff
# for the output directories use the mk1mf.pl values with "_nw" appended
if ($shlib)
{
   if ($LIBC)
   {
      $out_def.="_nw_libc_nlm";
      $tmp_def.="_nw_libc_nlm";
      $inc_def.="_nw_libc_nlm";
   }
   else  # NETWARE_CLIB
   {
      $out_def.="_nw_clib_nlm";
      $tmp_def.="_nw_clib_nlm";
      $inc_def.="_nw_clib_nlm";
   }
}
else
{
   $libp=".lib";
   $shlibp=".lib";
   $lib_flags="-nodefaults -type library";
   if ($LIBC)
   {
      $out_def.="_nw_libc";
      $tmp_def.="_nw_libc";
      $inc_def.="_nw_libc";
   }
   else  # NETWARE_CLIB 
   {
      $out_def.="_nw_clib";
      $tmp_def.="_nw_clib";
      $inc_def.="_nw_clib";
   }
}

# used by mk1mf.pl
$obj='.obj';
$ofile='-o ';
$efile='';
$exep='.nlm';
$ex_libs='';

if (!$no_asm)
{
   $bn_asm_obj="crypto${o}bn${o}asm${o}bn-nw.obj";
   $bn_asm_src="crypto${o}bn${o}asm${o}bn-nw.asm";
   $des_enc_obj="crypto${o}des${o}asm${o}d-nw.obj crypto${o}des${o}asm${o}y-nw.obj";
   $des_enc_src="crypto${o}des${o}asm${o}d-nw.asm crypto${o}des${o}asm${o}y-nw.asm";
   $bf_enc_obj="crypto${o}bf${o}asm${o}b-nw.obj";
   $bf_enc_src="crypto${o}bf${o}asm${o}b-nw.asm";
   $cast_enc_obj="crypto${o}cast${o}asm${o}c-nw.obj";
   $cast_enc_src="crypto${o}cast${o}asm${o}c-nw.asm";
   $rc4_enc_obj="crypto${o}rc4${o}asm${o}r4-nw.obj";
   $rc4_enc_src="crypto${o}rc4${o}asm${o}r4-nw.asm";
   $rc5_enc_obj="crypto${o}rc5${o}asm${o}r5-nw.obj";
   $rc5_enc_src="crypto${o}rc5${o}asm${o}r5-nw.asm";
   $md5_asm_obj="crypto${o}md5${o}asm${o}m5-nw.obj";
   $md5_asm_src="crypto${o}md5${o}asm${o}m5-nw.asm";
   $sha1_asm_obj="crypto${o}sha${o}asm${o}s1-nw.obj";
   $sha1_asm_src="crypto${o}sha${o}asm${o}s1-nw.asm";
   $rmd160_asm_obj="crypto${o}ripemd${o}asm${o}rm-nw.obj";
   $rmd160_asm_src="crypto${o}ripemd${o}asm${o}rm-nw.asm";
   $cflags.=" -DBN_ASM -DMD5_ASM -DSHA1_ASM -DRMD160_ASM";
}
else
{
   $bn_asm_obj='';
   $bn_asm_src='';
   $des_enc_obj='';
   $des_enc_src='';
   $bf_enc_obj='';
   $bf_enc_src='';
   $cast_enc_obj='';
   $cast_enc_src='';
   $rc4_enc_obj='';
   $rc4_enc_src='';
   $rc5_enc_obj='';
   $rc5_enc_src='';
   $md5_asm_obj='';
   $md5_asm_src='';
   $sha1_asm_obj='';
   $sha1_asm_src='';
   $rmd160_asm_obj='';
   $rmd160_asm_src='';
}

# create the *.def linker command files in \openssl\netware\ directory
sub do_def_file
{
   # strip off the leading path
   my($target) = bname(@_);
   my($def_file);
   my($mod_file);
   my($i);

   if ($target =~ /(.*).nlm/)
   {
      $target = $1;
   }

   # special case for openssl - the mk1mf.pl defines E_EXE = openssl
   if ($target =~ /E_EXE/)
   {
      $target = "openssl";
   }

   # Note: originally tried to use full path ( \openssl\netware\$target.def )
   # Metrowerks linker choked on this with an assertion failure. bug???
   #
   $def_file = "netware\\$target.def";

   open(DEF_OUT, ">$def_file") || die("unable to open file $def_file\n");

   print( DEF_OUT "# command file generated by netware.pl for Metrowerks build\n" );
   print( DEF_OUT "#\n");
   print( DEF_OUT "DESCRIPTION \"$target\"\n");
   
   foreach $i (@misc_imports)
   {
      print( DEF_OUT "IMPORT $i\n");
   }
   
   foreach $i (@import_files)
   {
      print( DEF_OUT "IMPORT \@$import_path\\$i\n");
   }
   
   foreach $i (@module_files)
   {
      print( DEF_OUT "MODULE $i\n");
   }

   close(DEF_OUT);
   return($def_file);
}

sub do_lib_rule
{
   my($objs,$target,$name,$shlib)=@_;
   my($ret);

   $ret.="$target: $objs\n";
   if (!$shlib)
   {
      $ret.="\t\@echo Building Lib: $name\n";
      $ret.="\t\$(MKLIB) $lib_flags -o $target $objs\n";
      $ret.="\t\@echo .\n"
   }
   else
   {
      die( "Building as NLM not currently supported!" );
   }

   $ret.="\n";
   return($ret);
}

sub do_link_rule
{
   my($target,$files,$dep_libs,$libs)=@_;
   my($ret);
   my($def_file);

   $def_file = do_def_file($target);

   # special case for openssl - the mk1mf.pl defines E_EXE = openssl

   # NOTE:  When building the test nlms no screen name is given
   #  which causes the console screen to be used.  By using the console
   #  screen there is no "<press any key to continue>" message which
   #  requires user interaction.  The test script ( tests.pl ) needs to be
   #  able to run the tests without requiring user interaction.
   #
   #  However, the sample program "openssl.nlm" is used by the tests and is
   #  a interactive sample so a screen is desired when not be run by the
   #  tests.  To solve the problem, two versions of the program are built:
   #    openssl2 - no screen used by tests
   #    openssl - default screen - use for normal interactive modes
   #
   if ($target =~ /E_EXE/)
   {
      my($target2) = $target;

      $target2 =~ s/\(E_EXE\)/\(E_EXE\)2/;

      $ret.="$target: $files $dep_libs\n";

         # openssl
      $ret.="\t\$(LINK) \$(LFLAGS) -screenname openssl -commandfile $def_file $files \"$prelude\" $libs -o $target\n";
         # openssl2
      $ret.="\t\$(LINK) \$(LFLAGS) -commandfile $def_file $files \"$prelude\" $libs -o $target2\n";
   }
   else
   {
      $ret.="$target: $files $dep_libs\n";
      $ret.="\t\$(LINK) \$(LFLAGS) -commandfile $def_file $files \"$prelude\" $libs -o $target\n";
   }

   $ret.="\n";
   return($ret);
}

1;
