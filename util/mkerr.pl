#!/usr/local/bin/perl -w

my $config = "crypto/err/openssl.ec";
my $debug = 0;
my $rebuild = 0;
my $static = 1;
my $recurse = 0;
my $reindex = 0;
my $dowrite = 0;
my $staticloader = "";

while (@ARGV) {
	my $arg = $ARGV[0];
	if($arg eq "-conf") {
		shift @ARGV;
		$config = shift @ARGV;
	} elsif($arg eq "-debug") {
		$debug = 1;
		shift @ARGV;
	} elsif($arg eq "-rebuild") {
		$rebuild = 1;
		shift @ARGV;
	} elsif($arg eq "-recurse") {
		$recurse = 1;
		shift @ARGV;
	} elsif($arg eq "-reindex") {
		$reindex = 1;
		shift @ARGV;
	} elsif($arg eq "-nostatic") {
		$static = 0;
		shift @ARGV;
	} elsif($arg eq "-staticloader") {
		$staticloader = "static ";
		shift @ARGV;
	} elsif($arg eq "-write") {
		$dowrite = 1;
		shift @ARGV;
	} else {
		last;
	}
}

if($recurse) {
	@source = (<crypto/*.c>, <crypto/*/*.c>, <ssl/*.c>);
} else {
	@source = @ARGV;
}

# Read in the config file

open(IN, "<$config") || die "Can't open config file $config";

# Parse config file

while(<IN>)
{
	if(/^L\s+(\S+)\s+(\S+)\s+(\S+)/) {
		$hinc{$1} = $2;
		$libinc{$2} = $1;
		$cskip{$3} = $1;
		if($3 ne "NONE") {
			$csrc{$1} = $3;
			$fmax{$1} = 99;
			$rmax{$1} = 99;
			$fnew{$1} = 0;
			$rnew{$1} = 0;
		}
	} elsif (/^F\s+(\S+)/) {
	# Add extra function with $1
	} elsif (/^R\s+(\S+)\s+(\S+)/) {
		$rextra{$1} = $2;
		$rcodes{$1} = $2;
	}
}

close IN;

# Scan each header file in turn and make a list of error codes
# and function names

while (($hdr, $lib) = each %libinc)
{
	next if($hdr eq "NONE");
	print STDERR "Scanning header file $hdr\n" if $debug; 
	my $line = "", $def= "", $linenr = 0, $gotfile = 0;
	if (open(IN, "<$hdr")) {
	    $gotfile = 1;
	    while(<IN>) {
		$linenr++;
		print STDERR "line: $linenr\r" if $debug;

		last if(/BEGIN\s+ERROR\s+CODES/);
		if ($line ne '') {
		    $_ = $line . $_;
		    $line = '';
		}

		if (/\\$/) {
		    $line = $_;
		    next;
		}

		$cpp = 1 if /^#.*ifdef.*cplusplus/;  # skip "C" declaration
		if ($cpp) {
		    $cpp = 0 if /^#.*endif/;
		    next;
		}

		next if (/^\#/);                      # skip preprocessor directives

		s/\/\*.*?\*\///gs;                   # ignore comments
		s/{[^{}]*}//gs;                      # ignore {} blocks

		if (/\{|\/\*/) { # Add a } so editor works...
		    $line = $_;
		} else {
		    $def .= $_;
		}
	    }
	}

	print STDERR "                                  \r" if $debug;
        $defnr = 0;
	foreach (split /;/, $def) {
	    $defnr++;
	    print STDERR "def: $defnr\r" if $debug;

	    s/^[\n\s]*//g;
	    s/[\n\s]*$//g;
	    next if(/typedef\W/);
	    if (/\(\*(\w*)\([^\)]+/) {
		my $name = $1;
		$name =~ tr/[a-z]/[A-Z]/;
		$ftrans{$name} = $1;
	    } elsif (/\w+\W+(\w+)\W*\(\s*\)$/s){
		# K&R C
		next ;
	    } elsif (/\w+\W+\w+\W*\(.*\)$/s) {
		while (not /\(\)$/s) {
		    s/[^\(\)]*\)$/\)/s;
		    s/\([^\(\)]*\)\)$/\)/s;
		}
		s/\(void\)//;
		/(\w+)\W*\(\)/s;
		my $name = $1;
		$name =~ tr/[a-z]/[A-Z]/;
		$ftrans{$name} = $1;
	    } elsif (/\(/ and not (/=/ or /DECLARE_STACK/)) {
		print STDERR "Header $hdr: cannot parse: $_;\n";
	    }
	}

	print STDERR "                                  \r" if $debug;

	next if $reindex;

	# Scan function and reason codes and store them: keep a note of the
	# maximum code used.

	if ($gotfile) {
	    while(<IN>) {
		if(/^\#define\s+(\S+)\s+(\S+)/) {
			$name = $1;
			$code = $2;
			next if $name =~ /^${lib}err/;
			unless($name =~ /^${lib}_([RF])_(\w+)$/) {
				print STDERR "Invalid error code $name\n";
				next;
			}
			if($1 eq "R") {
				$rcodes{$name} = $code;
				if(!(exists $rextra{$name}) &&
					 ($code > $rmax{$lib}) ) {
					$rmax{$lib} = $code;
				}
			} else {
				if($code > $fmax{$lib}) {
					$fmax{$lib} = $code;
				}
				$fcodes{$name} = $code;
			}
		}
	    }
	}
	close IN;
}

# Scan each C source file and look for function and reason codes
# This is done by looking for strings that "look like" function or
# reason codes: basically anything consisting of all upper case and
# numerics which has _F_ or _R_ in it and which has the name of an
# error library at the start. This seems to work fine except for the
# oddly named structure BIO_F_CTX which needs to be ignored.
# If a code doesn't exist in list compiled from headers then mark it
# with the value "X" as a place holder to give it a value later.
# Store all function and reason codes found in %ufcodes and %urcodes
# so all those unreferenced can be printed out.


print STDERR "Files loaded: " if $debug;
foreach $file (@source) {
	# Don't parse the error source file.
	next if exists $cskip{$file};
	print STDERR $file if $debug;
	open(IN, "<$file") || die "Can't open source file $file\n";
	while(<IN>) {
		if(/(([A-Z0-9]+)_F_([A-Z0-9_]+))/) {
			next unless exists $csrc{$2};
			next if($1 eq "BIO_F_BUFFER_CTX");
			$ufcodes{$1} = 1;
			if(!exists $fcodes{$1}) {
				$fcodes{$1} = "X";
				$fnew{$2}++;
			}
			$notrans{$1} = 1 unless exists $ftrans{$3};
		}
		if(/(([A-Z0-9]+)_R_[A-Z0-9_]+)/) {
			next unless exists $csrc{$2};
			$urcodes{$1} = 1;
			if(!exists $rcodes{$1}) {
				$rcodes{$1} = "X";
				$rnew{$2}++;
			}
		} 
	}
	close IN;
}
print STDERR "\n" if $debug;

# Now process each library in turn.

foreach $lib (keys %csrc)
{
	my $hfile = $hinc{$lib};
	my $cfile = $csrc{$lib};
	if(!$fnew{$lib} && !$rnew{$lib}) {
		print STDERR "$lib:\t\tNo new error codes\n";
		next unless $rebuild;
	} else {
		print STDERR "$lib:\t\t$fnew{$lib} New Functions,";
		print STDERR " $rnew{$lib} New Reasons.\n";
		next unless $dowrite;
	}

	# If we get here then we have some new error codes so we
	# need to rebuild the header file and C file.

	# Make a sorted list of error and reason codes for later use.

	my @function = sort grep(/^${lib}_/,keys %fcodes);
	my @reasons = sort grep(/^${lib}_/,keys %rcodes);

	# Rewrite the header file

	if (open(IN, "<$hfile")) {
	    # Copy across the old file
	    while(<IN>) {
		push @out, $_;
		last if (/BEGIN ERROR CODES/);
	    }
	    close IN;
	} else {
	    push @out,
"/* ====================================================================\n",
" * Copyright (c) 2001-2002 The OpenSSL Project.  All rights reserved.\n",
" *\n",
" * Redistribution and use in source and binary forms, with or without\n",
" * modification, are permitted provided that the following conditions\n",
" * are met:\n",
" *\n",
" * 1. Redistributions of source code must retain the above copyright\n",
" *    notice, this list of conditions and the following disclaimer. \n",
" *\n",
" * 2. Redistributions in binary form must reproduce the above copyright\n",
" *    notice, this list of conditions and the following disclaimer in\n",
" *    the documentation and/or other materials provided with the\n",
" *    distribution.\n",
" *\n",
" * 3. All advertising materials mentioning features or use of this\n",
" *    software must display the following acknowledgment:\n",
" *    \"This product includes software developed by the OpenSSL Project\n",
" *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)\"\n",
" *\n",
" * 4. The names \"OpenSSL Toolkit\" and \"OpenSSL Project\" must not be used to\n",
" *    endorse or promote products derived from this software without\n",
" *    prior written permission. For written permission, please contact\n",
" *    openssl-core\@openssl.org.\n",
" *\n",
" * 5. Products derived from this software may not be called \"OpenSSL\"\n",
" *    nor may \"OpenSSL\" appear in their names without prior written\n",
" *    permission of the OpenSSL Project.\n",
" *\n",
" * 6. Redistributions of any form whatsoever must retain the following\n",
" *    acknowledgment:\n",
" *    \"This product includes software developed by the OpenSSL Project\n",
" *    for use in the OpenSSL Toolkit (http://www.openssl.org/)\"\n",
" *\n",
" * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY\n",
" * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n",
" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n",
" * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR\n",
" * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n",
" * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n",
" * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n",
" * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n",
" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n",
" * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n",
" * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n",
" * OF THE POSSIBILITY OF SUCH DAMAGE.\n",
" * ====================================================================\n",
" *\n",
" * This product includes cryptographic software written by Eric Young\n",
" * (eay\@cryptsoft.com).  This product includes software written by Tim\n",
" * Hudson (tjh\@cryptsoft.com).\n",
" *\n",
" */\n",
"\n",
"#ifndef HEADER_${lib}_ERR_H\n",
"#define HEADER_${lib}_ERR_H\n",
"\n",
"/* BEGIN ERROR CODES */\n";
	}
	open (OUT, ">$hfile") || die "Can't Open File $hfile for writing\n";

	print OUT @out;
	undef @out;
	print OUT <<"EOF";
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
EOF
	if($static) {
		print OUT <<"EOF";
${staticloader}void ERR_load_${lib}_strings(void);

EOF
	} else {
		print OUT <<"EOF";
${staticloader}void ERR_load_${lib}_strings(void);
${staticloader}void ERR_unload_${lib}_strings(void);
${staticloader}void ERR_${lib}_error(int function, int reason, char *file, int line);
#define ${lib}err(f,r) ERR_${lib}_error((f),(r),__FILE__,__LINE__)

EOF
	}
	print OUT <<"EOF";
/* Error codes for the $lib functions. */

/* Function codes. */
EOF

	foreach $i (@function) {
		$z=6-int(length($i)/8);
		if($fcodes{$i} eq "X") {
			$fcodes{$i} = ++$fmax{$lib};
			print STDERR "New Function code $i\n" if $debug;
		}
		printf OUT "#define $i%s $fcodes{$i}\n","\t" x $z;
	}

	print OUT "\n/* Reason codes. */\n";

	foreach $i (@reasons) {
		$z=6-int(length($i)/8);
		if($rcodes{$i} eq "X") {
			$rcodes{$i} = ++$rmax{$lib};
			print STDERR "New Reason code   $i\n" if $debug;
		}
		printf OUT "#define $i%s $rcodes{$i}\n","\t" x $z;
	}
	print OUT <<"EOF";

#ifdef  __cplusplus
}
#endif
#endif
EOF
	close OUT;

	# Rewrite the C source file containing the error details.

	# First, read any existing reason string definitions:
	my %err_reason_strings;
	if (open(IN,"<$cfile")) {
		while (<IN>) {
			if (/\b(${lib}_R_\w*)\b.*\"(.*)\"/) {
				$err_reason_strings{$1} = $2;
			}
		}
		close(IN);
	}

	my $hincf;
	if($static) {
		$hfile =~ /([^\/]+)$/;
		$hincf = "<openssl/$1>";
	} else {
		$hincf = "\"$hfile\"";
	}


	open (OUT,">$cfile") || die "Can't open $cfile for writing";

	print OUT <<"EOF";
/* $cfile */
/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core\@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay\@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh\@cryptsoft.com).
 *
 */

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include $hincf

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA ${lib}_str_functs[]=
	{
EOF
	# Add each function code: if a function name is found then use it.
	foreach $i (@function) {
		my $fn;
		$i =~ /^${lib}_F_(\S+)$/;
		$fn = $1;
		if(exists $ftrans{$fn}) {
			$fn = $ftrans{$fn};
		}
		print OUT "{ERR_PACK(0,$i,0),\t\"$fn\"},\n";
	}
	print OUT <<"EOF";
{0,NULL}
	};

static ERR_STRING_DATA ${lib}_str_reasons[]=
	{
EOF
	# Add each reason code.
	foreach $i (@reasons) {
		my $rn;
		my $nspc = 0;
		if (exists $err_reason_strings{$i}) {
			$rn = $err_reason_strings{$i};
		} else {
			$i =~ /^${lib}_R_(\S+)$/;
			$rn = $1;
			$rn =~ tr/_[A-Z]/ [a-z]/;
		}
		$nspc = 40 - length($i) unless length($i) > 40;
		$nspc = " " x $nspc;
		print OUT "{${i}${nspc},\"$rn\"},\n";
	}
if($static) {
	print OUT <<"EOF";
{0,NULL}
	};

#endif

${staticloader}void ERR_load_${lib}_strings(void)
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(ERR_LIB_${lib},${lib}_str_functs);
		ERR_load_strings(ERR_LIB_${lib},${lib}_str_reasons);
#endif

		}
	}
EOF
} else {
	print OUT <<"EOF";
{0,NULL}
	};

#endif

#ifdef ${lib}_LIB_NAME
static ERR_STRING_DATA ${lib}_lib_name[]=
        {
{0	,${lib}_LIB_NAME},
{0,NULL}
	};
#endif


static int ${lib}_lib_error_code=0;
static int ${lib}_error_init=1;

${staticloader}void ERR_load_${lib}_strings(void)
	{
	if (${lib}_lib_error_code == 0)
		${lib}_lib_error_code=ERR_get_next_error_library();

	if (${lib}_error_init)
		{
		${lib}_error_init=0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(${lib}_lib_error_code,${lib}_str_functs);
		ERR_load_strings(${lib}_lib_error_code,${lib}_str_reasons);
#endif

#ifdef ${lib}_LIB_NAME
		${lib}_lib_name->error = ERR_PACK(${lib}_lib_error_code,0,0);
		ERR_load_strings(0,${lib}_lib_name);
#endif
		}
	}

${staticloader}void ERR_unload_${lib}_strings(void)
	{
	if (${lib}_error_init == 0)
		{
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(${lib}_lib_error_code,${lib}_str_functs);
		ERR_unload_strings(${lib}_lib_error_code,${lib}_str_reasons);
#endif

#ifdef ${lib}_LIB_NAME
		ERR_unload_strings(0,${lib}_lib_name);
#endif
		${lib}_error_init=1;
		}
	}

${staticloader}void ERR_${lib}_error(int function, int reason, char *file, int line)
	{
	if (${lib}_lib_error_code == 0)
		${lib}_lib_error_code=ERR_get_next_error_library();
	ERR_PUT_error(${lib}_lib_error_code,function,reason,file,line);
	}
EOF

}

	close OUT;
	undef %err_reason_strings;
}

if($debug && defined(%notrans)) {
	print STDERR "The following function codes were not translated:\n";
	foreach(sort keys %notrans)
	{
		print STDERR "$_\n";
	}
}

# Make a list of unreferenced function and reason codes

foreach (keys %fcodes) {
	push (@funref, $_) unless exists $ufcodes{$_};
}

foreach (keys %rcodes) {
	push (@runref, $_) unless exists $urcodes{$_};
}

if($debug && defined(@funref) ) {
	print STDERR "The following function codes were not referenced:\n";
	foreach(sort @funref)
	{
		print STDERR "$_\n";
	}
}

if($debug && defined(@runref) ) {
	print STDERR "The following reason codes were not referenced:\n";
	foreach(sort @runref)
	{
		print STDERR "$_\n";
	}
}
