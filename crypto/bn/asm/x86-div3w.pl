#!/usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is dual licensed under OpenSSL and CRYPTOGAMS
# licenses depending on where you obtain it. For further details see
# https://github.com/dot-asm/cryptogams/.
# ====================================================================

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

$output = pop;
open STDOUT,">$output";

&asm_init($ARGV[0]);

&function_begin("bn_div_3_words");
	&mov	("esi",&wparam(0));
	&mov	("ebx",&wparam(1));		# load D
	&mov	("ecx",&wparam(2));
	&stack_push(2);
	&mov	("edx",&DWP(-4,"esi"));		# load R
	&mov	("esi",&DWP(0,"esi"));
	&xor	("eax","eax");			# Q = 0
	&mov	("ebp",32);			# loop counter

&set_label("loop",16);
	&lea	("eax",&DWP(1,"eax","eax"));	# Q <<= 1 + speculative bit 
	&mov	(&swtmp(0),"edx");		# put aside R
	&sub	("edx","ebx");			# R -= D
	&mov	(&swtmp(1),"esi");
	&sbb	("esi","ecx");
	&mov	("edi",1);
	&sbb	("eax",0);			# subtract speculative bit
	&and	("edi","eax");
	&xor	("edx",&swtmp(0));		# select between R and R - D
	&neg	("edi");			# 0 - least significant bit
	&xor	("esi",&swtmp(1));
	 &shr	("ebx",1);			# D >>= 1
	&and	("edx","edi");
	&and	("esi","edi");
	 &mov	("edi","ecx");
	&xor	("edx",&swtmp(0));
	 &shl	("edi",31);
	&xor	("esi",&swtmp(1));
	 &shr	("ecx",1);
	 &or	("ebx","edi");
	&dec	("ebp");
	&jnz	(&label("loop"));

	&lea	("ebp",&DWP(1,"eax","eax"));	# Q <<= 1 + speculative but
	&sar	("eax",31);			# top bit -> mask

	&sub	("edx","ebx");			# R -= D
	&sbb	("esi","ecx");
	&sbb	("ebp",0);			# subtract speculative bit

	&or	("eax","ebp");			# all ones if overflow

	&stack_pop(2);
&function_end("bn_div_3_words");

&asm_finish();

close STDOUT;
