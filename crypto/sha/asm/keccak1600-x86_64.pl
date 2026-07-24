#!/usr/bin/env perl
# Copyright 2017-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see https://github.com/dot-asm/cryptogams/.
# ====================================================================
#
# Keccak-1600 for x86_64.
#
# June 2017.
#
# Below code is [lane complementing] KECCAK_2X implementation (see
# sha/keccak1600.c) with C[5] and D[5] held in register bank. Though
# instead of actually unrolling the loop pair-wise I simply flip
# pointers to T[][] and A[][] at the end of round. Since number of
# rounds is even, last round writes to A[][] and everything works out.
# How does it compare to x86_64 assembly module in Keccak Code Package?
# Depending on processor it's either as fast or faster by up to 15%...
#
########################################################################
# Numbers are cycles per processed byte out of large message.
#
#			r=1088(*)
#
# P4			25.8
# Core 2		12.9
# Westmere		13.7
# Sandy Bridge		12.9(**)
# Haswell		9.6
# Skylake		9.4
# Silvermont		22.8
# Goldmont		15.8
# VIA Nano		17.3
# Sledgehammer		13.3
# Bulldozer		16.5
# Ryzen			8.8
#
# (*)	Corresponds to SHA3-256. Improvement over compiler-generate
#	varies a lot, most common coefficient is 15% in comparison to
#	gcc-5.x, 50% for gcc-4.x, 90% for gcc-3.x.
# (**)	Sandy Bridge has broken rotate instruction. Performance can be
#	improved by 14% by replacing rotates with double-precision
#	shift with same register as source and destination.

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

my @A = map([ 8*$_-100, 8*($_+1)-100, 8*($_+2)-100,
              8*($_+3)-100, 8*($_+4)-100 ], (0,5,10,15,20));

my @C = ("%rax","%rbx","%rcx","%rdx","%rbp");
my @D = map("%r$_",(8..12));
my @T = map("%r$_",(13..14));
my $iotas = "%r15";

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

$code.=<<___;
.text

.type	__KeccakF1600,\@abi-omnipotent
.align	32
__KeccakF1600:
.cfi_startproc
	mov	$A[4][0](%rdi),@C[0]
	mov	$A[4][1](%rdi),@C[1]
	mov	$A[4][2](%rdi),@C[2]
	mov	$A[4][3](%rdi),@C[3]
	mov	$A[4][4](%rdi),@C[4]
	jmp	.Loop

.align	32
.Loop:
	mov	$A[0][0](%rdi),@D[0]
	mov	$A[1][1](%rdi),@D[1]
	mov	$A[2][2](%rdi),@D[2]
	mov	$A[3][3](%rdi),@D[3]

	xor	$A[0][2](%rdi),@C[2]
	xor	$A[0][3](%rdi),@C[3]
	xor	@D[0],         @C[0]
	xor	$A[0][1](%rdi),@C[1]
	 xor	$A[1][2](%rdi),@C[2]
	 xor	$A[1][0](%rdi),@C[0]
	mov	@C[4],@D[4]
	xor	$A[0][4](%rdi),@C[4]

	xor	@D[2],         @C[2]
	xor	$A[2][0](%rdi),@C[0]
	 xor	$A[1][3](%rdi),@C[3]
	 xor	@D[1],         @C[1]
	 xor	$A[1][4](%rdi),@C[4]

	xor	$A[3][2](%rdi),@C[2]
	xor	$A[3][0](%rdi),@C[0]
	 xor	$A[2][3](%rdi),@C[3]
	 xor	$A[2][1](%rdi),@C[1]
	 xor	$A[2][4](%rdi),@C[4]

	mov	@C[2],@T[0]
	rol	\$1,@C[2]
	xor	@C[0],@C[2]		# D[1] = ROL64(C[2], 1) ^ C[0]
	 xor	@D[3],         @C[3]

	rol	\$1,@C[0]
	xor	@C[3],@C[0]		# D[4] = ROL64(C[0], 1) ^ C[3]
	 xor	$A[3][1](%rdi),@C[1]

	rol	\$1,@C[3]
	xor	@C[1],@C[3]		# D[2] = ROL64(C[3], 1) ^ C[1]
	 xor	$A[3][4](%rdi),@C[4]

	rol	\$1,@C[1]
	xor	@C[4],@C[1]		# D[0] = ROL64(C[1], 1) ^ C[4]

	rol	\$1,@C[4]
	xor	@T[0],@C[4]		# D[3] = ROL64(C[4], 1) ^ C[2]
___
	(@D[0..4], @C) = (@C[1..4,0], @D);
$code.=<<___;
	xor	@D[1],@C[1]
	xor	@D[2],@C[2]
	rol	\$$rhotates[1][1],@C[1]
	xor	@D[3],@C[3]
	xor	@D[4],@C[4]
	rol	\$$rhotates[2][2],@C[2]
	xor	@D[0],@C[0]
	 mov	@C[1],@T[0]
	rol	\$$rhotates[3][3],@C[3]
	 or	@C[2],@C[1]
	 xor	@C[0],@C[1]		#           C[0] ^ ( C[1] | C[2])
	rol	\$$rhotates[4][4],@C[4]

	 xor	($iotas),@C[1]
	 lea	8($iotas),$iotas

	mov	@C[4],@T[1]
	and	@C[3],@C[4]
	 mov	@C[1],$A[0][0](%rsi)	# R[0][0] = C[0] ^ ( C[1] | C[2]) ^ iotas[i]
	xor	@C[2],@C[4]		#           C[2] ^ ( C[4] & C[3])
	not	@C[2]
	mov	@C[4],$A[0][2](%rsi)	# R[0][2] = C[2] ^ ( C[4] & C[3])

	or	@C[3],@C[2]
	  mov	$A[4][2](%rdi),@C[4]
	xor	@T[0],@C[2]		#           C[1] ^ (~C[2] | C[3])
	mov	@C[2],$A[0][1](%rsi)	# R[0][1] = C[1] ^ (~C[2] | C[3])

	and	@C[0],@T[0]
	  mov	$A[1][4](%rdi),@C[1]
	xor	@T[1],@T[0]		#           C[4] ^ ( C[1] & C[0])
	  mov	$A[2][0](%rdi),@C[2]
	mov	@T[0],$A[0][4](%rsi)	# R[0][4] = C[4] ^ ( C[1] & C[0])

	or	@C[0],@T[1]
	  mov	$A[0][3](%rdi),@C[0]
	xor	@C[3],@T[1]		#           C[3] ^ ( C[4] | C[0])
	  mov	$A[3][1](%rdi),@C[3]
	mov	@T[1],$A[0][3](%rsi)	# R[0][3] = C[3] ^ ( C[4] | C[0])


	xor	@D[3],@C[0]
	xor	@D[2],@C[4]
	rol	\$$rhotates[0][3],@C[0]
	xor	@D[1],@C[3]
	xor	@D[4],@C[1]
	rol	\$$rhotates[4][2],@C[4]
	rol	\$$rhotates[3][1],@C[3]
	xor	@D[0],@C[2]
	rol	\$$rhotates[1][4],@C[1]
	 mov	@C[0],@T[0]
	 or	@C[4],@C[0]
	rol	\$$rhotates[2][0],@C[2]

	xor	@C[3],@C[0]		#           C[3] ^ (C[0] |  C[4])
	mov	@C[0],$A[1][3](%rsi)	# R[1][3] = C[3] ^ (C[0] |  C[4])

	mov	@C[1],@T[1]
	and	@T[0],@C[1]
	  mov	$A[0][1](%rdi),@C[0]
	xor	@C[4],@C[1]		#           C[4] ^ (C[1] &  C[0])
	not	@C[4]
	mov	@C[1],$A[1][4](%rsi)	# R[1][4] = C[4] ^ (C[1] &  C[0])

	or	@C[3],@C[4]
	  mov	$A[1][2](%rdi),@C[1]
	xor	@C[2],@C[4]		#           C[2] ^ (~C[4] | C[3])
	mov	@C[4],$A[1][2](%rsi)	# R[1][2] = C[2] ^ (~C[4] | C[3])

	and	@C[2],@C[3]
	  mov	$A[4][0](%rdi),@C[4]
	xor	@T[1],@C[3]		#           C[1] ^ (C[3] &  C[2])
	mov	@C[3],$A[1][1](%rsi)	# R[1][1] = C[1] ^ (C[3] &  C[2])

	or	@C[2],@T[1]
	  mov	$A[2][3](%rdi),@C[2]
	xor	@T[0],@T[1]		#           C[0] ^ (C[1] |  C[2])
	  mov	$A[3][4](%rdi),@C[3]
	mov	@T[1],$A[1][0](%rsi)	# R[1][0] = C[0] ^ (C[1] |  C[2])


	xor	@D[3],@C[2]
	xor	@D[4],@C[3]
	rol	\$$rhotates[2][3],@C[2]
	xor	@D[2],@C[1]
	rol	\$$rhotates[3][4],@C[3]
	xor	@D[0],@C[4]
	rol	\$$rhotates[1][2],@C[1]
	xor	@D[1],@C[0]
	rol	\$$rhotates[4][0],@C[4]
	 mov	@C[2],@T[0]
	 and	@C[3],@C[2]
	rol	\$$rhotates[0][1],@C[0]

	not	@C[3]
	xor	@C[1],@C[2]		#            C[1] ^ ( C[2] & C[3])
	mov	@C[2],$A[2][1](%rsi)	# R[2][1] =  C[1] ^ ( C[2] & C[3])

	mov	@C[4],@T[1]
	and	@C[3],@C[4]
	  mov	$A[2][1](%rdi),@C[2]
	xor	@T[0],@C[4]		#            C[2] ^ ( C[4] & ~C[3])
	mov	@C[4],$A[2][2](%rsi)	# R[2][2] =  C[2] ^ ( C[4] & ~C[3])

	or	@C[1],@T[0]
	  mov	$A[4][3](%rdi),@C[4]
	xor	@C[0],@T[0]		#            C[0] ^ ( C[2] | C[1])
	mov	@T[0],$A[2][0](%rsi)	# R[2][0] =  C[0] ^ ( C[2] | C[1])

	and	@C[0],@C[1]
	xor	@T[1],@C[1]		#            C[4] ^ ( C[1] & C[0])
	mov	@C[1],$A[2][4](%rsi)	# R[2][4] =  C[4] ^ ( C[1] & C[0])

	or	@C[0],@T[1]
	  mov	$A[1][0](%rdi),@C[1]
	xor	@C[3],@T[1]		#           ~C[3] ^ ( C[0] | C[4])
	  mov	$A[3][2](%rdi),@C[3]
	mov	@T[1],$A[2][3](%rsi)	# R[2][3] = ~C[3] ^ ( C[0] | C[4])


	mov	$A[0][4](%rdi),@C[0]

	xor	@D[1],@C[2]
	xor	@D[2],@C[3]
	rol	\$$rhotates[2][1],@C[2]
	xor	@D[0],@C[1]
	rol	\$$rhotates[3][2],@C[3]
	xor	@D[3],@C[4]
	rol	\$$rhotates[1][0],@C[1]
	xor	@D[4],@C[0]
	rol	\$$rhotates[4][3],@C[4]
	 mov	@C[2],@T[0]
	 or	@C[3],@C[2]
	rol	\$$rhotates[0][4],@C[0]

	not	@C[3]
	xor	@C[1],@C[2]		#            C[1] ^ ( C[2] | C[3])
	mov	@C[2],$A[3][1](%rsi)	# R[3][1] =  C[1] ^ ( C[2] | C[3])

	mov	@C[4],@T[1]
	or	@C[3],@C[4]
	xor	@T[0],@C[4]		#            C[2] ^ ( C[4] | ~C[3])
	mov	@C[4],$A[3][2](%rsi)	# R[3][2] =  C[2] ^ ( C[4] | ~C[3])

	and	@C[1],@T[0]
	xor	@C[0],@T[0]		#            C[0] ^ ( C[2] & C[1])
	mov	@T[0],$A[3][0](%rsi)	# R[3][0] =  C[0] ^ ( C[2] & C[1])

	or	@C[0],@C[1]
	xor	@T[1],@C[1]		#            C[4] ^ ( C[1] | C[0])
	mov	@C[1],$A[3][4](%rsi)	# R[3][4] =  C[4] ^ ( C[1] | C[0])

	and	@T[1],@C[0]
	xor	@C[3],@C[0]		#           ~C[3] ^ ( C[0] & C[4])
	mov	@C[0],$A[3][3](%rsi)	# R[3][3] = ~C[3] ^ ( C[0] & C[4])


	xor	$A[0][2](%rdi),@D[2]
	xor	$A[1][3](%rdi),@D[3]
	rol	\$$rhotates[0][2],@D[2]
	xor	$A[4][1](%rdi),@D[1]
	rol	\$$rhotates[1][3],@D[3]
	xor	$A[2][4](%rdi),@D[4]
	rol	\$$rhotates[4][1],@D[1]
	xor	$A[3][0](%rdi),@D[0]
	xchg	%rsi,%rdi
	rol	\$$rhotates[2][4],@D[4]
	rol	\$$rhotates[3][0],@D[0]
___
	@C = @D[2..4,0,1];
$code.=<<___;
	mov	@C[0],@T[0]
	and	@C[1],@C[0]
	not	@C[1]
	xor	@C[4],@C[0]		#            C[4] ^ ( C[0] & C[1])
	mov	@C[0],$A[4][4](%rdi)	# R[4][4] =  C[4] ^ ( C[0] & C[1])

	mov	@C[2],@T[1]
	and	@C[1],@C[2]
	xor	@T[0],@C[2]		#            C[0] ^ ( C[2] & ~C[1])
	mov	@C[2],$A[4][0](%rdi)	# R[4][0] =  C[0] ^ ( C[2] & ~C[1])

	or	@C[4],@T[0]
	xor	@C[3],@T[0]		#            C[3] ^ ( C[0] | C[4])
	mov	@T[0],$A[4][3](%rdi)	# R[4][3] =  C[3] ^ ( C[0] | C[4])

	and	@C[3],@C[4]
	xor	@T[1],@C[4]		#            C[2] ^ ( C[4] & C[3])
	mov	@C[4],$A[4][2](%rdi)	# R[4][2] =  C[2] ^ ( C[4] & C[3])

	or	@T[1],@C[3]
	xor	@C[1],@C[3]		#           ~C[1] ^ ( C[2] | C[3])
	mov	@C[3],$A[4][1](%rdi)	# R[4][1] = ~C[1] ^ ( C[2] | C[3])

	mov	@C[0],@C[1]		# harmonize with the loop top
	mov	@T[0],@C[0]

	test	\$255,$iotas
	jnz	.Loop

	lea	-192($iotas),$iotas	# rewind iotas
	ret
.cfi_endproc
.size	__KeccakF1600,.-__KeccakF1600

___

sub x86_64_lane_complement {
    $code.=<<___;
	notq	$A[0][1](%rdi)
	notq	$A[0][2](%rdi)
	notq	$A[1][3](%rdi)
	notq	$A[2][2](%rdi)
	notq	$A[3][2](%rdi)
	notq	$A[4][0](%rdi)
___
}

sub gen_keccak1600_wrapper {
    my ($name, $iotas_base) = @_;

    $code.=<<___;
.type	$name,\@abi-omnipotent
.align	32
$name:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15

	lea	100(%rdi),%rdi		# size optimization
	sub	\$200,%rsp
.cfi_adjust_cfa_offset	200

___
    x86_64_lane_complement();

    $code.=<<___;
	lea	$iotas_base(%rip),$iotas
	lea	100(%rsp),%rsi		# size optimization

	call	__KeccakF1600

___
    x86_64_lane_complement();

    $code.=<<___;
	lea	-100(%rdi),%rdi		# preserve A[][]

	add	\$200,%rsp
.cfi_adjust_cfa_offset	-200

	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
	pop	%rbp
.cfi_pop	%rbp
	pop	%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	$name,.-$name
___
}

gen_keccak1600_wrapper("KeccakF1600", "iotas");
gen_keccak1600_wrapper("KeccakP1600_12", "96+iotas");

{ my ($A_flat,$inp,$len,$bsz) = ("%rdi","%rsi","%rdx","%rcx");
     ($A_flat,$inp) = ("%r8","%r9");

sub gen_absorb {
    my ($name, $suffix, $init_iotas, $round_iotas) = @_;

    $code.=<<___;
.globl	$name
.type	$name,\@function,4
.align	32
$name:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15

	lea	100(%rdi),%rdi		# size optimization
	sub	\$232,%rsp
.cfi_adjust_cfa_offset	232

	mov	%rsi,$inp
	lea	100(%rsp),%rsi		# size optimization

___
    x86_64_lane_complement();
    $code .= $init_iotas;
    $code.=<<___;
	mov	$bsz,216-100(%rsi)	# save bsz

.Loop_absorb$suffix:
	cmp	$bsz,$len
	jc	.Ldone_absorb$suffix

	shr	\$3,$bsz
	lea	-100(%rdi),$A_flat

.Lblock_absorb$suffix:
	mov	($inp),%rax
	lea	8($inp),$inp
	xor	($A_flat),%rax
	lea	8($A_flat),$A_flat
	sub	\$8,$len
	mov	%rax,-8($A_flat)
	sub	\$1,$bsz
	jnz	.Lblock_absorb$suffix

	mov	$inp,200-100(%rsi)	# save inp
	mov	$len,208-100(%rsi)	# save len
___
    $code .= $round_iotas;
    $code.=<<___;
	call	__KeccakF1600
	mov	200-100(%rsi),$inp	# pull inp
	mov	208-100(%rsi),$len	# pull len
	mov	216-100(%rsi),$bsz	# pull bsz
	jmp	.Loop_absorb$suffix

.align	32
.Ldone_absorb$suffix:
	mov	$len,%rax		# return value

___
    x86_64_lane_complement();

    $code.=<<___;

	add	\$232,%rsp
.cfi_adjust_cfa_offset	-232

	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
	pop	%rbp
.cfi_pop	%rbp
	pop	%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	$name,.-$name
___
}
gen_absorb("SHA3_absorb", "", "\tlea\tiotas(%rip),$iotas\n\n", "");
gen_absorb("ossl_keccak1600_absorb_p12", "_p12", "",
           "\tlea\t96+iotas(%rip),$iotas\n");
}
{ my ($A_flat,$out,$len,$bsz,$next) = ("%rdi","%rsi","%rdx","%rcx","%r8");
     ($out,$len,$bsz) = ("%r12","%r13","%r14");

sub gen_squeeze {
    my ($name, $suffix, $round_func, $r12_cfi) = @_;

    $code.=<<___;
.globl	$name
.type	$name,\@function,5
.align	32
$name:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14

	shr	\$3,%rcx
	mov	$A_flat,%r9
	mov	%rsi,$out
	mov	%rdx,$len
	mov	%rcx,$bsz
	bt	\$0,${next}d
	jc	.Lnext_block$suffix
	jmp	.Loop_squeeze$suffix

.align	32
.Loop_squeeze$suffix:
	cmp	\$8,$len
	jb	.Ltail_squeeze$suffix

	mov	(%r9),%rax
	lea	8(%r9),%r9
	mov	%rax,($out)
	lea	8($out),$out
	sub	\$8,$len		# len -= 8
	jz	.Ldone_squeeze$suffix

	sub	\$1,%rcx		# bsz--
	jnz	.Loop_squeeze$suffix
.Lnext_block$suffix:
	call	$round_func
	mov	$A_flat,%r9
	mov	$bsz,%rcx
	jmp	.Loop_squeeze$suffix

.Ltail_squeeze$suffix:
	mov	%r9, %rsi
	mov	$out,%rdi
	mov	$len,%rcx
	.byte	0xf3,0xa4		# rep	movsb

.Ldone_squeeze$suffix:
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	$r12_cfi
	ret
.cfi_endproc
.size	$name,.-$name
___
}
gen_squeeze("SHA3_squeeze", "", "KeccakF1600", "%r13");
gen_squeeze("ossl_keccak1600_squeeze_p12", "_p12", "KeccakP1600_12", "%r12");
}
$code.=<<___;
.section .rodata align=256
.align	256
	.quad	0,0,0,0,0,0,0,0
.type	iotas,\@object
iotas:
	.quad	0x0000000000000001
	.quad	0x0000000000008082
	.quad	0x800000000000808a
	.quad	0x8000000080008000
	.quad	0x000000000000808b
	.quad	0x0000000080000001
	.quad	0x8000000080008081
	.quad	0x8000000000008009
	.quad	0x000000000000008a
	.quad	0x0000000000000088
	.quad	0x0000000080008009
	.quad	0x000000008000000a
	.quad	0x000000008000808b
	.quad	0x800000000000008b
	.quad	0x8000000000008089
	.quad	0x8000000000008003
	.quad	0x8000000000008002
	.quad	0x8000000000000080
	.quad	0x000000000000800a
	.quad	0x800000008000000a
	.quad	0x8000000080008081
	.quad	0x8000000000008080
	.quad	0x0000000080000001
	.quad	0x8000000080008008
.size	iotas,.-iotas
.asciz	"Keccak-1600 absorb and squeeze for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
___

foreach (split("\n",$code)) {
	# Below replacement results in 11.2 on Sandy Bridge, 9.4 on
	# Haswell, but it hurts other processors by up to 2-3-4x...
	#s/rol\s+(\$[0-9]+),(%[a-z][a-z0-9]+)/shld\t$1,$2,$2/;
	# Below replacement results in 9.3 on Haswell [as well as
	# on Ryzen, i.e. it *hurts* Ryzen]...
	#s/rol\s+\$([0-9]+),(%[a-z][a-z0-9]+)/rorx\t\$64-$1,$2,$2/;

	print $_, "\n";
}

close STDOUT or die "error closing STDOUT: $!";
