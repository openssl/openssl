#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
<<<<<<< HEAD
# This module implements support for SM4 hw aesni support on x86
# Implement the ECB, CBC and CTR modes in Unix X86, because the ways
# to passing parameters between caller and callee are different in 
# Unix and Win64, here just implement the Unix version.
=======
# This module implements support for SM4 hw support on aarch64
>>>>>>> 203cc7fe937d0c28d8660609563e67e27807129b
# Aug. 2022
#

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;
$win64=0;

@_4args=$win64?	("%rcx","%rdx","%r8", "%r9") :	# Win64 order
		("%rdi","%rsi","%rdx","%rcx");	# Unix order

$PREFIX = "aesni_sm4";

{{{
$code.=<<___;
.arch x86-64
.text
.align 0x10
Lc0f:
	.space	16,15
Lflp:
	.long 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F
Lm1l:
	.long 0x74720701, 0x9197E2E4, 0x22245157, 0xC7C1B4B2
Lm1h:
	.long 0xEB49A200, 0xE240AB09, 0xF95BB012, 0xF052B91B
Lshr:
	.long 0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C
Lm2l:
	.long 0xA19D0834, 0x5B67F2CE, 0x172BBE82, 0xEDD14478
Lm2h:
	.long 0x73AFDC00, 0xAE7201DD, 0xCC1063BF, 0x11CDBE62
Lr24:
	.long 0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D
Lr16:
	.long 0x01000302, 0x05040706, 0x09080B0A, 0x0D0C0F0E
Lr08:
	.long 0x02010003, 0x06050407, 0x0A09080B, 0x0E0D0C0F
Linc:
	.long	0, 0, 0, 0x1   
___
}}}


{{{
$code.=<<___;
.p2align	4 
.space 16
Llow4:
	.long 0x0, 0x10, 0x20, 0x30
Lmid4:
	.long 0x4, 0x14, 0x24, 0x34
Lupper4:
	.long 0x8, 0x18, 0x28, 0x38
Lhigh4:
	.long 0xc, 0x1c, 0x2c, 0x3c
___
}}}

sub aesni_F{
my ($y, $x)=("%xmm10", "%xmm0");
my ($c0f, $m1l, $m1h, $shr, $m2l, $m2h, $r08, $r16, $r24)=map("%xmm$_",(11, 12, 12, 12, 12,12,12,12,12));
$code.=<<___;
    
    vmovdqa	Lc0f(%rip), $c0f            ## xmm1 = [15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15]
	# inner affine
    vpand	$c0f, $x, $y
	vmovdqa	Lm1l(%rip), $m1l            ## xmm3 = [1,7,114,116,228,226,151,145,87,81,36,34,178,180,193,199]
	vpshufb	$y, $m1l, $y
	vpsrlq	\$4, $x, $x
	vpand	$c0f, $x, $x
	vmovdqa	Lm1h(%rip), $m1h            ## xmm3 = [0,162,73,235,9,171,64,226,18,176,91,249,27,185,82,240]
	vpshufb	$x, $m1h, $x
	vmovdqa	Lshr(%rip), $shr            ## xmm3 = [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]
	vpshufb	$shr, $y, $y
	vpshufb	$shr, $x, $x
	vpxor	$y, $x, $x
	vaesenclast	Lc0f(%rip), $x, $x
    # outter affine
	vpandn	$c0f, $x, $y
	vmovdqa	Lm2l(%rip), $m2l            ## xmm3 = [52,8,157,161,206,242,103,91,130,190,43,23,120,68,209,237]
	vpshufb	$y, $m2l, $y
	vpsrlq	\$4, $x, $x
	vpand	$c0f, $x, $x
	vmovdqa	Lm2h(%rip), $m2h            ## xmm1 = [0,220,175,115,221,1,114,174,191,99,16,204,98,190,205,17]
	vpshufb	$x, $m2h, $x
	vpxor	$y, $x, $x
    # Linear transform
	vpshufb	Lr08(%rip), $x, %xmm11     ## xmm1 = xmm0[3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14]
	vpxor	$x, %xmm11, %xmm11
	vpshufb	Lr16(%rip), $x, $y     ## xmm2 = xmm0[2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13]
	vpxor	$y, %xmm11, %xmm11
	vpsrld	\$30, %xmm11, $y
	vpslld	\$2, %xmm11, %xmm11
	vpor	$y, %xmm11, %xmm11
	vpshufb	Lr24(%rip), $x, $y     ## xmm2 = xmm0[1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12]
    vpxor	$x, $y, $x
    vpxor	%xmm11, $x, $x

___
}


sub loadu32{
my ($oft, $dst)=@_;
$code.=<<___;
    movq	%r13, %rdi
	movl	\$$oft, %esi

    movl	%esi, %eax
    movzbl	(%rdi,%rax), %eax
    shll	\$24, %eax
    leal	1(%rsi), %ecx
    movzbl	(%rdi,%rcx), %ecx
    shll	\$16, %ecx
	or	%eax, %ecx
	leal	2(%rsi), %eax
	movzbl	(%rdi,%rax), %edx
	shll	\$8, %edx
	or	%ecx, %edx
    addl	\$3, %esi
    movzbl	(%rdi,%rsi), %eax
    or	%edx, %eax

    movl	%eax, $dst
___
}

sub storeu32{
my ($src, $oft)=@_;
$code.=<<___;
    leaq	$oft(%r15), %rsi
    movl	$src, %edi
    movbel	%edi, (%rsi)
___
}

{{{
my ($in, $out, $key, $dump) = @_4args;
my ($x0, $x1, $x2, $x3) = ("%r12", "%r14", "%ebx", "%eax");
$code.=<<___;
.globl	${PREFIX}_encrypt
	.p2align	4, 0x90
${PREFIX}_encrypt:  
.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$24, %rsp
	movq	$key, -56(%rbp)                 
    movq	$out, -48(%rbp)                 
    movq	$in, %r13
___

    &loadu32("0", "${x0}d");
    &loadu32("4", "${x1}d");
    &loadu32("8", "$x2");
    &loadu32("12", "$x3");

$code.=<<___;
    xorl	%r15d, %r15d
    .p2align	4, 0x90
Len1:                                
    movl	${x1}d, %r13d
    movl	$x2, ${x1}d
    movl	$x3, $x2
    movl	${x1}d, $x3
	xorl	%r13d, $x3
    xorl	$x2, $x3
	movq	-56(%rbp), %rcx                
    xorl	(%rcx,%r15,4), $x3
    vmovd	$x3, %xmm0
	vpbroadcastd	%xmm0, %xmm0
___
    &aesni_F();

$code.=<<___;
    vmovd	%xmm0, $x3
    xorl	${x0}d, $x3
    movl	%r13d, ${x0}d

    incq	%r15
    cmpq	\$32, %r15
    jne	Len1

	movq	-48(%rbp), %r15  
___

    &storeu32("$x3", "0");
    &storeu32("$x2", "4");
    &storeu32("${x1}d", "8");
    &storeu32("${x0}d", "12");
    
$code.=<<___;
	addq	\$24, %rsp
	popq	%rbx
    popq	%r12
	popq	%r13
    popq	%r14
    popq	%r15
	popq	%rbp
    retq
.cfi_endproc
___
}}}


{{{
my ($in, $out, $key, $dump) = @_4args;
my ($x0, $x1, $x2, $x3) = ("%r12", "%r14", "%ebx", "%eax");
$code.=<<___;
.globl	${PREFIX}_decrypt
	.p2align	4, 0x90
${PREFIX}_decrypt:  
.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$24, %rsp
	movq	$key, -56(%rbp)                 
    movq	$out, -48(%rbp)                 
    movq	$in, %r13
___

    &loadu32("0", "${x0}d");
    &loadu32("4", "${x1}d");
    &loadu32("8", "$x2");
    &loadu32("12", "$x3");

$code.=<<___;
    movl	\$31, %r15d
    .p2align	4, 0x90
Lde1:                                
    movl	${x1}d, %r13d
    movl	$x2, ${x1}d
    movl	$x3, $x2
    movl	${x1}d, $x3
	xorl	%r13d, $x3
    xorl	$x2, $x3
	movq	-56(%rbp), %rcx                
    xorl	(%rcx,%r15,4), $x3
    vmovd	$x3, %xmm0
	vpbroadcastd	%xmm0, %xmm0
___
    &aesni_F();

$code.=<<___;
    vmovd	%xmm0, $x3
    xorl	${x0}d, $x3
    movl	%r13d, ${x0}d

    addq    \$-1,   %r15
    jb	Lde1

	movq	-48(%rbp), %r15  
___

    &storeu32("$x3", "0");
    &storeu32("$x2", "4");
    &storeu32("${x1}d", "8");
    &storeu32("${x0}d", "12");
    
$code.=<<___;
	addq	\$24, %rsp
	popq	%rbx
    popq	%r12
	popq	%r13
    popq	%r14
    popq	%r15
	popq	%rbp
    retq
.cfi_endproc
___
}}}



sub unroll_x{
my ($a0, $a1, $a2, $a3, $key, $op) = @_;
$code.=<<___;
    # vmovdqa %xmm0, %xmm14
    vpbroadcastd ($key,%rax,4), %xmm5
    vpxor $a1, $a2, %xmm0
    vpxor $a3, %xmm0, %xmm0
    vpxor %xmm5, %xmm0, %xmm0
___
    &aesni_F();
$code.=<<___;
    vpxor %xmm0, $a0, $a0
    # vmovdqa %xmm14, %xmm0
    $op	%rax
___
}

sub load_and_set{

my ($pc, $in, $mem, $target, $flp, $tmp0, $tmp1, $tmp2) = @_;

$code.=<<___;
    vmovdqa	$mem($pc), $tmp0           
	vpcmpeqd	$tmp1, $tmp1, $tmp1
	vpgatherdd	$tmp1, ($in,$tmp0), $target
	vpshufb	$flp, $target, $target
___

}

sub store_shuffle{
my ($src, $out, $fst0, $fst1, $fst2, $fst3,  $flp) = @_;

$code.=<<___;
    vpshufb	$flp, $src, $src

    vpextrd	\$0, $src, $fst0($out)
    vpextrd	\$1, $src, $fst1($out)
	vpextrd	\$2, $src, $fst2($out)
	vpextrd	\$3, $src, $fst3($out)
___

}

{{{
my ($in, $out, $key, $dump) = @_4args;
my $pc = "%rip";
# %xmm register layout
my ($r0, $r1, $r2, $r3)=map("%xmm$_",(13, 14, 8, 7));

my ($y2, $y10, $y18, $y24)=("%xmm6", "%xmm7", "%xmm6", "%xmm4");

my $flp = "%xmm4";

$code.=<<___;
.globl	${PREFIX}_ecb_encrypt4
	.p2align	4, 0x90
${PREFIX}_ecb_encrypt4:  
.cfi_startproc
    vmovdqa	Lflp($pc), $flp            # # xmm6 = [3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
___

    &load_and_set($pc, $in, "Llow4", $r0, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lmid4", $r1, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lupper4", $r2, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lhigh4", $r3, $flp, "%xmm1", "%xmm2", "%xmm3");

$code.=<<___;
	xorl %eax, %eax
LEINN:
___

    &unroll_x($r0, $r1, $r2, $r3, $key, "incq");
    &unroll_x($r1, $r0, $r2, $r3, $key, "incq");
    &unroll_x($r2, $r1, $r0, $r3, $key, "incq");
    &unroll_x($r3, $r1, $r2, $r0, $key, "incq");

$code.=<<___;
    cmpq	\$32, %rax
	jne	LEINN
    vmovdqa	Lflp($pc), $flp            # #  xmm4 = [3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
___

    &store_shuffle($r3, $out, "0", "16", "32", "48", $flp);
    &store_shuffle($r2, $out, "4", "20", "36", "52", $flp);
    &store_shuffle($r1, $out, "8", "24", "40", "56", $flp);
    &store_shuffle($r0, $out, "12", "28", "44", "60", $flp);

$code.=<<___;
	retq
.cfi_endproc
___

}}}


{{{
my ($in, $out, $key, $dump) = @_4args;
my $pc = "%rip";
# %xmm register layout
my ($r0, $r1, $r2, $r3)=map("%xmm$_",(13, 14, 8, 7));

my ($y2, $y10, $y18, $y24)=("%xmm6", "%xmm7", "%xmm6", "%xmm4");

my $flp = "%xmm4";

$code.=<<___;
.globl	${PREFIX}_ecb_decrypt4
	.p2align	4, 0x90
${PREFIX}_ecb_decrypt4:  
.cfi_startproc
    vmovdqa	Lflp($pc), $flp            # # xmm6 = [3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
___

    &load_and_set($pc, $in, "Llow4", $r0, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lmid4", $r1, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lupper4", $r2, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lhigh4", $r3, $flp, "%xmm1", "%xmm2", "%xmm3");

$code.=<<___;
	movl	\$31, %eax
LDINN:
___

    &unroll_x($r0, $r1, $r2, $r3, $key, "addq	\$-1,");
    &unroll_x($r1, $r0, $r2, $r3, $key, "addq	\$-1,");
    &unroll_x($r2, $r1, $r0, $r3, $key, "addq	\$-1,");
    &unroll_x($r3, $r1, $r2, $r0, $key, "addq	\$-1,");

$code.=<<___;
	jb	LDINN
    vmovdqa	Lflp($pc), $flp            # #  xmm4 = [3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
___

    &store_shuffle($r3, $out, "0", "16", "32", "48", $flp);
    &store_shuffle($r2, $out, "4", "20", "36", "52", $flp);
    &store_shuffle($r1, $out, "8", "24", "40", "56", $flp);
    &store_shuffle($r0, $out, "12", "28", "44", "60", $flp);

$code.=<<___;
	retq
.cfi_endproc
___
}}}


{{{
$code.=<<___;
.globl	${PREFIX}_ecb_encrypt
	.p2align	4, 0x90
${PREFIX}_ecb_encrypt:                
.cfi_startproc
	pushq	%rbp
	movq	%rsp, %rbp
	subq	\$80, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	%rcx, -32(%rbp)
	movl	%r8d, -36(%rbp)

	movq	-8(%rbp), %rax
	movq	%rax, -48(%rbp)
	movq	-16(%rbp), %rax
	movq	%rax, -56(%rbp)
	movq	-24(%rbp), %rax
	andq	\$63, %rax
	movl	%eax, -60(%rbp)
	movq	-24(%rbp), %rax
	shrq	\$6, %rax
	movl	%eax, -64(%rbp)

	cmpl	\$0, -36(%rbp) # # goto decrypt
	je	Lecb_dec

	movl	\$0, -68(%rbp)
Lecb_enc_L:                                 # # encrypt
	movl	-68(%rbp), %eax
	cmpl	-64(%rbp), %eax
	jge	Lecb_enc_rem

	movq	-48(%rbp), %rdi
	movl	-68(%rbp), %eax
	shll	\$6, %eax
	cltq
	addq	%rax, %rdi
	movq	-56(%rbp), %rsi
	movl	-68(%rbp), %eax
	shll	\$6, %eax
	cltq
	addq	%rax, %rsi
	movq	-32(%rbp), %rdx
	callq	${PREFIX}_ecb_encrypt4
	movl	-68(%rbp), %eax
	addl	\$1, %eax
	movl	%eax, -68(%rbp)
	jmp	Lecb_enc_L
Lecb_enc_rem:
	cmpl	\$0, -60(%rbp)
	jle	Lecb_ret
	jmp	Lecb_encrypt_tail


Lecb_dec:		# # decrypt
	movl	\$0, -72(%rbp)
Lecb_dec_L:                              
	movl	-72(%rbp), %eax
	cmpl	-64(%rbp), %eax
	jge	Lecb_dec_rem
	movq	-48(%rbp), %rdi
	movl	-72(%rbp), %eax
	shll	\$6, %eax
	cltq
	addq	%rax, %rdi
	movq	-56(%rbp), %rsi
	movl	-72(%rbp), %eax
	shll	\$6, %eax
	cltq
	addq	%rax, %rsi
	movq	-32(%rbp), %rdx
	callq	${PREFIX}_ecb_decrypt4
	movl	-72(%rbp), %eax
	addl	\$1, %eax
	movl	%eax, -72(%rbp)
	jmp	Lecb_dec_L
Lecb_dec_rem:
	cmpl	\$0, -60(%rbp)
	jle	Lecb_ret
	jmp	Lecb_decrypt_tail

Lecb_encrypt_tail:
	movq	-24(%rbp), %rax
	movslq	-60(%rbp), %rcx
	subq	%rcx, %rax
	movl	%eax, -76(%rbp)
Lecb_enc_tail_L:                              
	movslq	-76(%rbp), %rax
	cmpq	-24(%rbp), %rax
	jae	Lecb_ret
	movq	-48(%rbp), %rdi
	movslq	-76(%rbp), %rax
	addq	%rax, %rdi
	movq	-56(%rbp), %rsi
	movslq	-76(%rbp), %rax
	addq	%rax, %rsi
	movq	-32(%rbp), %rdx
	callq	${PREFIX}_encrypt
	movl	-76(%rbp), %eax
	addl	\$16, %eax
	movl	%eax, -76(%rbp)
	jmp	Lecb_enc_tail_L

Lecb_decrypt_tail:
	movq	-24(%rbp), %rax
	movslq	-60(%rbp), %rcx
	subq	%rcx, %rax
	movl	%eax, -80(%rbp)
Lecb_dec_tail_L:                              
	movslq	-80(%rbp), %rax
	cmpq	-24(%rbp), %rax
	jae	Lecb_ret
	movq	-48(%rbp), %rdi
	movslq	-80(%rbp), %rax
	addq	%rax, %rdi
	movq	-56(%rbp), %rsi
	movslq	-80(%rbp), %rax
	addq	%rax, %rsi
	movq	-32(%rbp), %rdx
	callq	${PREFIX}_decrypt
	movl	-80(%rbp), %eax
	addl	\$16, %eax
	movl	%eax, -80(%rbp)
	jmp	Lecb_dec_tail_L

Lecb_ret:
	addq	\$80, %rsp
	popq	%rbp
	retq
.cfi_endproc
___
}}}


sub set_mask{
    my ($ivx0, $ivx1, $ivx2, $ivx3, $ofst, $dst)=@_;
$code.=<<___;
    pextrd $ofst, $ivx0, %r10d
    pextrd $ofst, $ivx1, %r11d
    pextrd $ofst, $ivx2, %r12d
    pextrd $ofst, $ivx3, %r13d

    vmovd	%r10d, $dst
	vpinsrd	\$1, %r11d, $dst, $dst
	vpinsrd	\$2, %r12d, $dst, $dst
	vpinsrd	\$3, %r13d, $dst, $dst
___
}

{{{
my ($in, $out, $key, $ivec, $val) = ("%rdi", "%rsi", "%rdx", "%rcx", "%r8");
my $pc = "%rip";
# %xmm register layout
my ($r0, $r1, $r2, $r3)=map("%xmm$_",(13, 14, 8, 7)); 
my ($ivx0, $ivx1, $ivx2, $ivx3)=map("%xmm$_",(1, 2, 3, 4));
my ($p0, $p1, $p2, $p3)=map("%xmm$_",(10, 11, 9, 4));

my $flp = "%xmm6";

$code.=<<___;
.globl	${PREFIX}_ctr_encrypt4
	.p2align	4, 0x90
${PREFIX}_ctr_encrypt4:  
.cfi_startproc          
	pushq	%rbp
	movq	%rsp, %rbp
    pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%rbx
	subq	\$40, %rsp

	vmovdqu	($ivec), $ivx0
	vpshufb	Lflp($pc), $ivx0, $ivx0     ## xmm0 = xmm0[3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
	vmovd	${val}d, $ivx1
	vpslldq	\$12, $ivx1, $ivx1               ## xmm1 = zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,xmm1[0,1,2,3]
	vpaddd	$ivx0, $ivx1, $ivx0
	vpaddd	Linc($pc), $ivx0, $ivx1
	vpaddd	Linc($pc), $ivx1, $ivx2
	vpaddd	Linc($pc), $ivx2, $ivx3

___
    &set_mask($ivx0, $ivx1, $ivx2, $ivx3, "\$0", $r0);
    &set_mask($ivx0, $ivx1, $ivx2, $ivx3, "\$1", $r1);
    &set_mask($ivx0, $ivx1, $ivx2, $ivx3, "\$2", $r2);
    &set_mask($ivx0, $ivx1, $ivx2, $ivx3, "\$3", $r3);

$code.=<<___;

	xorl	%eax, %eax
	.p2align	4, 0x90
Lctren4:   
___

    &unroll_x($r0, $r1, $r2, $r3, $key, "incq");
    &unroll_x($r1, $r0, $r2, $r3, $key, "incq");
    &unroll_x($r2, $r1, $r0, $r3, $key, "incq");
    &unroll_x($r3, $r1, $r2, $r0, $key, "incq");

$code.=<<___;

	cmpq	\$32, %rax
	jne	Lctren4
    
    vmovdqa	Lflp($pc), $flp            # # xmm6 = [3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
___

    &load_and_set($pc, $in, "Llow4", $p0, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lmid4", $p1, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lupper4", $p2, $flp, "%xmm1", "%xmm2", "%xmm3");
    &load_and_set($pc, $in, "Lhigh4", $p3, $flp, "%xmm1", "%xmm2", "%xmm3");

$code.=<<___;

    vpxor $r3, $p0, $r3
    vpxor $r2, $p1, $r2
    vpxor $r1, $p2, $r1
    vpxor $r0, $p3, $r0

    vmovdqa	Lflp($pc), $flp
___

    &store_shuffle($r3, $out, "0", "16", "32", "48", $flp);
    &store_shuffle($r2, $out, "4", "20", "36", "52", $flp);
    &store_shuffle($r1, $out, "8", "24", "40", "56", $flp);
    &store_shuffle($r0, $out, "12", "28", "44", "60", $flp);

$code.=<<___;
    addq	\$40, %rsp
	popq	%rbx
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
	popq	%rbp

    retq
	.cfi_endproc
___
}}}


{{{
my ($in, $out, $len, $key, $ivec, $val) = ("%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9");

my $ivx0 = "%xmm1";
my $pc = "%rip";

my $x = "%xmm0";
my $y = "%ebx";
my ($r0, $r1, $r2, $r3)=("%r10d", "%r11d", "%r12d", "%r13d");

$code.=<<___;
.globl	${PREFIX}_ctr_encrypt1
	.p2align	4, 0x90
${PREFIX}_ctr_encrypt1:  
.cfi_startproc 
    pushq	%rbp
	movq	%rsp, %rbp
    pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%rbx
	subq	\$40, %rsp

    vmovdqu	($ivec), $ivx0
	vpshufb	Lflp($pc), $ivx0, $ivx0     ## xmm0 = xmm0[3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12]
    vmovd	${val}d, %xmm2
	vpslldq	\$12, %xmm2, %xmm2               ## xmm1 = zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,zero,xmm1[0,1,2,3]
	vpaddd	$ivx0, %xmm2, $ivx0

    pextrd \$0, $ivx0, $r0
    pextrd \$1, $ivx0, $r1
    pextrd \$2, $ivx0, $r2
    pextrd \$3, $ivx0, $r3

    xorl	%eax, %eax
Lctren1:

    xorl    $y, $y
    xorl    $r1, $y
    xorl    $r2, $y
    xorl    $r3, $y
    xorl    ($key, %rax, 4), $y
    vpxor   $x, $x, $x
    vpxor   %xmm3, %xmm3, %xmm3
    vmovd   $y, %xmm3
    vpbroadcastd %xmm3, $x

___

    &aesni_F();

$code.=<<___;

    pextrd \$0, $x, $y
    xorl $r0, $y

    movl $r1, $r0
    movl $r2, $r1
    movl $r3, $r2
    movl $y,  $r3

    incq %rax
    cmp \$32, %rax
    jne Lctren1

    # store tmp

    movbel	$r3, (%rsp)
    movbel	$r2, 4(%rsp)
    movbel	$r1, 8(%rsp)
    movbel	$r0, 12(%rsp)


    xorl    %eax, %eax
Lctren1_st:

    movb    (%rsp, %rax), %bl
    xorb    ($in, %rax), %bl
    movb    %bl,    ($out, %rax)

    incq %rax
    cmp %rax, $len
    jne Lctren1_st

    addq	\$40, %rsp
	popq	%rbx
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
	popq	%rbp

    retq
.cfi_endproc
___
}}}


{{{

my ($in, $out, $blocks, $key, $ivec)=("%rdi", "%rsi", "%rdx", "%rcx", "%r8");

my ($in_org, $out_org, $blocks_org)=("%r15", "%r12", "%r13");

my $pc = "%rip";

$code.=<<___;
	.globl	${PREFIX}_ctr_encrypt      
	.p2align	4, 0x90
${PREFIX}_ctr_encrypt:                
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$40, %rsp

    movq	$blocks, $blocks_org
	movq	$out, $out_org
	movq	$in, $in_org
    
	movl	${blocks_org}d, %eax
	andl	\$3, %eax
	movl	%eax, -44(%rbp)              
	movq	%rdx, %rax
	shrq	\$2, %rax
	testl	%eax, %eax
	movq	%r8, -64(%rbp)                
	movq	%rcx, -56(%rbp)

	jle	Lctr_rem
	movl	%eax, %eax
	shlq	\$6, %rax
	movq	%rax, -72(%rbp)               
	xorl	%ebx, %ebx
	xorl	%r14d, %r14d

	.p2align	4, 0x90
Lctr_bulks:                               
	movslq	%ebx, %rsi
	leaq	($in_org,%rsi), %rdi
	addq	$out_org, %rsi
	movq	%rcx, %rdx
	movq	%r8, %rcx
	movl	%r14d, %r8d
	callq	${PREFIX}_ctr_encrypt4
	movq	-56(%rbp), %rcx                
	movq	-64(%rbp), %r8                
	addl	\$4, %r14d
	addq	\$64, %rbx
	cmpq	%rbx, -72(%rbp) 
	jne	Lctr_bulks

Lctr_rem:
	movl	-44(%rbp), %eax                 ## 4-byte Reload
	testl	%eax, %eax
	je	Lctr_ret
	andl	\$-4, ${blocks_org}d

	movl	%eax, %ebx
	.p2align	4, 0x90
Lctr_tail:                              
	leal	1($blocks_org), %r14d
	movq	$in_org, %rdi
	movq	$out_org, %rsi
	movl	\$16, %edx
	movq	-56(%rbp), %rcx                 ## 8-byte Reload
	movq	-64(%rbp), %r8                  ## 8-byte Reload
	movl	${blocks_org}d, %r9d
	callq	${PREFIX}_ctr_encrypt1
	addq	\$16, $in_org
	addq	\$16, $out_org
	movl	%r14d, ${blocks_org}d
	decq	%rbx
	jne	Lctr_tail

Lctr_ret:
	addq	\$40, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq
___

}}}

{{{
my ($in, $key) = ("%xmm0", "%rdi");
my ($r0, $r1, $r2, $r3) = ("%r12d", "%r13d", "%r14d", "%ebx");
my ($x, $y) = ("%r15d", "%r15d");

$code.=<<___;
	.globl	${PREFIX}_cbc_encrypt1        
	.p2align	4, 0x90
${PREFIX}_cbc_encrypt1:             
	.cfi_startproc
	
    pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$40, %rsp

    pextrd \$0, $in, $r0
    pextrd \$1, $in, $r1
    pextrd \$2, $in, $r2
    pextrd \$3, $in, $r3

    xorl %eax, %eax
Lcbc_enc1:
    xorl    $x, $x
    xorl    $r1, $x
    xorl    $r2, $x
    xorl    $r3, $x
    xorl    ($key, %rax, 4), $x

    vmovd	$x, %xmm0
	vpbroadcastd	%xmm0, %xmm0
___

    &aesni_F();

$code.=<<___;
    pextrd \$0, %xmm0, $y
    xorl    $r0, $y

    movl    $r1, $r0
    movl    $r2, $r1
    movl    $r3, $r2
    movl    $y, $r3

    incq %rax
    cmp \$32, %rax
    jne Lcbc_enc1

    vmovd	$r3, %xmm0
	vpinsrd	\$1, $r2, %xmm0, %xmm0
	vpinsrd	\$2, $r1, %xmm0, %xmm0
	vpinsrd	\$3, $r0, %xmm0, %xmm0


	addq	\$40, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq

	.cfi_endproc
___
}}}


{{{
my ($in, $key) = ("%xmm0", "%rdi");
my ($r0, $r1, $r2, $r3) = ("%r12d", "%r13d", "%r14d", "%ebx");
my ($x, $y) = ("%r15d", "%r15d");

$code.=<<___;
	.globl	${PREFIX}_cbc_decrypt1        
	.p2align	4, 0x90
${PREFIX}_cbc_decrypt1:             
	.cfi_startproc
	
    pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$40, %rsp

    pextrd \$0, $in, $r0
    pextrd \$1, $in, $r1
    pextrd \$2, $in, $r2
    pextrd \$3, $in, $r3

    movl \$31, %eax
Lcbc_de1:
    xorl    $x, $x
    xorl    $r1, $x
    xorl    $r2, $x
    xorl    $r3, $x
    xorl    ($key, %rax, 4), $x

    vmovd	$x, %xmm0
	vpbroadcastd	%xmm0, %xmm0
___

    &aesni_F();

$code.=<<___;
    pextrd \$0, %xmm0, $y
    xorl    $r0, $y

    movl    $r1, $r0
    movl    $r2, $r1
    movl    $r3, $r2
    movl    $y, $r3

    addq    \$-1, %rax
    jb	Lcbc_de1

    vmovd	$r3, %xmm0
	vpinsrd	\$1, $r2, %xmm0, %xmm0
	vpinsrd	\$2, $r1, %xmm0, %xmm0
	vpinsrd	\$3, $r0, %xmm0, %xmm0

	addq	\$40, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq

	.cfi_endproc
___

}}}

{{{

my ($r, $c, $p, $c_pre, $ivx) = map("%xmm$_",(2,3,4,5,6));
my ($in, $out, $len, $key, $ivec, $enc) = ("%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9");
my $pc = "%rip";

$code.=<<___;
.globl	${PREFIX}_cbc_encrypt      
	.p2align	4, 0x90
${PREFIX}_cbc_encrypt:                
.cfi_startproc
    pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	\$40, %rsp

    movq    $in, %rbx
    movq    $out, %r14
    movq    $key, %r13

    vmovdqu	($ivec), $ivx
    vpshufb	Lflp($pc), $ivx, $ivx

    shrq	\$4, $len
    testl   %edx, %edx
    jle  Lcbc_ret
    movl	%edx, %r12d

    testl   ${enc}d, ${enc}d
    je  Lcbc_dec
___

$code.=<<___;
Lcbc_enc:
    shlq	\$4, %r12
    movl    \$0, %r15d
    # encrypt the first block P_0
    vmovdqu	(%rbx), $p
    vpshufb	Lflp($pc), $p, $p
    vpxor   $ivx, $p, %xmm0
    movq    $key, %rdi
    callq ${PREFIX}_cbc_encrypt1
    vmovdqa %xmm0, $c
    vpshufb	Lflp($pc), $c, %xmm7
    vmovdqa	%xmm7, (%r14)

    addq	\$16, %r15
	cmpq	%r12, %r15
	jne	Lcbc_enc_L
    jmp Lcbc_ret

    # encrypt the rest blocks
Lcbc_enc_L:
    vmovdqu	(%rbx,%r15), $p
    vpshufb	Lflp($pc), $p, $p

    vpxor   $p, $c, %xmm0
    movq    $key, %rdi
    callq ${PREFIX}_cbc_encrypt1
    vmovdqa %xmm0, $c
    vpshufb	Lflp($pc), $c, %xmm7
    vmovdqa	%xmm7, (%r14, %r15)

    addq	\$16, %r15
	cmpq	%r12, %r15
	jne	Lcbc_enc_L
    jmp Lcbc_ret
___

$code.=<<___;
Lcbc_dec:
    shlq	\$4, %r12
    movl    \$0, %r15d
    # decrypt the first block C_0
    vmovdqu	(%rbx), $c
    vpshufb	Lflp($pc), $c, $c
    vmovdqa $c, %xmm0
    movq    $key, %rdi
    callq ${PREFIX}_cbc_decrypt1
    vpxor   $ivx, %xmm0, %xmm0
    vpshufb	Lflp($pc), %xmm0, $r
    vmovdqa	$r, (%r14)
    vmovdqa $c, $c_pre
    
    addq	\$16, %r15
	cmpq	%r12, %r15
	jne	Lcbc_dec_L
    jmp Lcbc_ret

    # decrypt the rest blocks
Lcbc_dec_L:
    vmovdqu	(%rbx,%r15), $c
    vpshufb	Lflp($pc), $c, $c
    vmovdqa $c, %xmm0
    movq    $key, %rdi
    callq ${PREFIX}_cbc_decrypt1
    vpxor   $c_pre, %xmm0, %xmm0
    vpshufb	Lflp($pc), %xmm0, $r
    vmovdqa	$r, (%r14, %r15)
    vmovdqa $c, $c_pre

    addq	\$16, %r15
	cmpq	%r12, %r15
	jne	Lcbc_dec_L

Lcbc_ret:
    addq	\$40, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp

    retq
	.cfi_endproc
___


}}}


open SELF,$0;
while(<SELF>) {
        next if (/^#!/);
        last if (!s/^#/\/\// and !/^$/);
        print;
}
close SELF;

foreach(split("\n",$code)) {
	s/\`([^\`]*)\`/eval($1)/ge;

	s/\b(sm4\w+)\s+([qv].*)/unsm4($1,$2)/ge;
	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
