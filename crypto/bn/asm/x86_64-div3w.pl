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

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code.=<<___;
.text

.globl	bn_div_3_words
.type	bn_div_3_words,\@function,3
.align	32
bn_div_3_words:
	mov	-8(%rdi),%r8		# load R.lo
	mov	(%rdi),%r9		# load R.hi
	xor	%rax,%rax		# Q = 0
	mov	\$64,%ecx		# loop counter

.Loop:
	mov	%r8,%r10		# put aside R
	sub	%rsi,%r8		# R -= D
	mov	%r9,%r11
	sbb	%rdx,%r9
	lea	1(%rax,%rax),%rax	# Q <<= 1 + speculative bit
	 mov	%rdx,%rdi
	cmovc	%r10,%r8		# restore R if R - D borrowed
	cmovc	%r11,%r9
	sbb	\$0,%rax		# subtract speculative bit
	 shl	\$63,%rdi
	 shr	\$1,%rsi
	 shr	\$1,%rdx
	 or	%rdi,%rsi		# D >>= 1
	sub	\$1,%ecx
	jnz	.Loop

	lea	1(%rax,%rax),%rcx	# Q <<= 1 + speculative bit
	sar	\$63,%rax		# top bit -> mask

	sub	%rsi,%r8		# R -= D
	sbb	%rdx,%r9
	sbb	\$0,%rcx		# subtract speculative bit

	or	%rcx,%rax		# all ones if overflow

	ret
.size	bn_div_3_words,.-bn_div_3_words
___

print $code;
close STDOUT;
