#!/usr/local/bin/perl

if ($ARGV[0] eq "-s") { $static=1; shift @ARGV; }

($#ARGV == 1) || die "usage: $0 [-s] <header file> <output C file>\n";
open(IN,"<$ARGV[0]") || die "unable to open $ARGV[0]:$!\n";
open(STDOUT,">$ARGV[1]") || die "unable to open $ARGV[1]:$!\n";

$Func=0;
$Reas=0;
$fuction{'FOPEN'}='fopen';
while (<IN>)
	{
	if (/(\S+)\s*\(\);/)
		{
		$t=$1;
		$t =~ s/\*//;
		($upper=$t) =~ tr/a-z/A-Z/;
		$fuction{$upper}=$t;
		}
	next unless (/^#define\s+(\S+)\s/);

	$o=$1;
	if ($o =~ /^([^_]+)_F_(.*)/)
		{
		$type=$1;
		$Func++;
		$n=$2;
		$n=$fuction{$n} if (defined($fuction{$n}));
		$out{$1."_str_functs"}.=
			sprintf("{ERR_PACK(0,%s,0),\t\"$n\"},\n",$o);
		}
	elsif ($o =~ /^([^_]+)_R_(.*)/)
		{
		$type=$1;
		$Reas++;
		$r=$2;
		$r =~ tr/A-Z_/a-z /;
		$pkg{$type."_str_reasons"}=$type;
		$out{$type."_str_reasons"}.=sprintf("{%-40s,\"$r\"},\n",$o);
		}
	elsif ($ARGV[0] =~ /rsaref/ && $o =~ /^RE_(.*)/)
		{
		$type="RSAREF";
		$Reas++;
		$r=$1;
		$r =~ tr/A-Z_/a-z /;
		$pkg{$type."_str_reasons"}=$type;
		$out{$type."_str_reasons"}.=sprintf("{%-40s,\"$r\"},\n",$o);
		}
	}
close(IN);

&header($type,$ARGV[0]);

foreach (sort keys %out)
	{
	print "static ERR_STRING_DATA ${_}[]=\n\t{\n";
	print $out{$_};
	print "{0,NULL},\n";
	print "\t};\n\n";
	}
print "#endif\n";

if ($static)
	{ $lib="ERR_LIB_$type"; }
else
	{ $lib="${type}_lib_error_code"; }

$str="";
$str.="#ifndef NO_ERR\n";
$str.="\t\tERR_load_strings($lib,${type}_str_functs);\n" if $Func;
$str.="\t\tERR_load_strings($lib,${type}_str_reasons);\n" if $Reas;
$str.="#endif\n";

if (!$static)
	{
print <<"EOF";

static int ${type}_lib_error_code=0;

void ERR_load_${type}_strings()
	{
	static int init=1;

	if (${type}_lib_error_code == 0)
		${type}_lib_error_code=ERR_get_next_error_library();

	if (init)
		{
		init=0;
$str
		}
	}

void ERR_${type}_error(function,reason,file,line)
int function;
int reason;
char *file;
int line;
	{
	if (${type}_lib_error_code == 0)
		${type}_lib_error_code=ERR_get_next_error_library();
	ERR_PUT_error(${type}_lib_error_code,function,reason,file,line);
	}
EOF
	}
else # $static
	{
	print <<"EOF";

void ERR_load_${type}_strings()
	{
	static int init=1;

	if (init)
		{
		init=0;
$str
		}
	}
EOF
	}

sub header
	{
	($type,$header)=@_;

	($lc=$type) =~ tr/A-Z/a-z/;
	$header =~ s/^.*\///;

	print "/* lib/$lc/${lc}\_err.c */\n";
	print <<'EOF';
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
EOF

	print "#include <stdio.h>\n";
	print "#include \"err.h\"\n";
	print "#include \"$header\"\n";
	print "\n/* BEGIN ERROR CODES */\n";
	print "#ifndef NO_ERR\n";
	}

