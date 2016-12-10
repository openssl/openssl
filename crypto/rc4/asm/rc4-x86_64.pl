#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================
#
# Unlike 0.9.7f this code expects RC4_CHAR back in config line! See
# commentary section in corresponding script in development branch
# for background information about this option carousel. For those
# who don't have energy to figure out these gory details, here is
# basis in form of performance matrix relative to the original
# 0.9.7e C code-base:
#
#		0.9.7e	0.9.7f	this
# AMD64		1x	3.3x	2.4x
# EM64T		1x	0.8x	1.5x
#
# In other words idea is to trade -25% AMD64 performance to compensate
# for deterioration and gain +90% on EM64T core. Development branch
# maintains best performance for either target, i.e. 3.3x for AMD64
# and 1.5x for EM64T.

$output=shift;

open STDOUT,">$output" || die "can't open $output: $!";

$dat="%rdi";	    # arg1
$len="%rsi";	    # arg2
$inp="%rdx";	    # arg3
$out="%rcx";	    # arg4

@XX=("%r8","%r10");
@TX=("%r9","%r11");
$YY="%r12";
$TY="%r13";

$code=<<___;;
.text

.globl	RC4
.type	RC4,\@function
.align	16
RC4:	or	$len,$len
	jne	.Lentry
	repret
.Lentry:
	push	%r12
	push	%r13

	add	\$2,$dat
	movzb	-2($dat),$XX[0]#d
	movzb	-1($dat),$YY#d

	add	\$1,$XX[0]#b
	movzb	($dat,$XX[0]),$TX[0]#d
	test	\$-8,$len
	jz	.Lcloop1
	push	%rbx
.align	16	# incidentally aligned already
.Lcloop8:
	mov	($inp),%eax
	mov	4($inp),%ebx
___
# unroll 2x4-wise, because 64-bit rotates kill Intel P4...
for ($i=0;$i<4;$i++) {
$code.=<<___;
	add	$TX[0]#b,$YY#b
	lea	1($XX[0]),$XX[1]
	movzb	($dat,$YY),$TY#d
	movzb	$XX[1]#b,$XX[1]#d
	movzb	($dat,$XX[1]),$TX[1]#d
	movb	$TX[0]#b,($dat,$YY)
	cmp	$XX[1],$YY
	movb	$TY#b,($dat,$XX[0])
	jne	.Lcmov$i			# Intel cmov is sloooow...
	mov	$TX[0],$TX[1]
.Lcmov$i:
	add	$TX[0]#b,$TY#b
	xor	($dat,$TY),%al
	ror	\$8,%eax
___
push(@TX,shift(@TX)); push(@XX,shift(@XX));	# "rotate" registers
}
for ($i=4;$i<8;$i++) {
$code.=<<___;
	add	$TX[0]#b,$YY#b
	lea	1($XX[0]),$XX[1]
	movzb	($dat,$YY),$TY#d
	movzb	$XX[1]#b,$XX[1]#d
	movzb	($dat,$XX[1]),$TX[1]#d
	movb	$TX[0]#b,($dat,$YY)
	cmp	$XX[1],$YY
	movb	$TY#b,($dat,$XX[0])
	jne	.Lcmov$i			# Intel cmov is sloooow...
	mov	$TX[0],$TX[1]
.Lcmov$i:
	add	$TX[0]#b,$TY#b
	xor	($dat,$TY),%bl
	ror	\$8,%ebx
___
push(@TX,shift(@TX)); push(@XX,shift(@XX));	# "rotate" registers
}
$code.=<<___;
	lea	-8($len),$len
	mov	%eax,($out)
	lea	8($inp),$inp
	mov	%ebx,4($out)
	lea	8($out),$out

	test	\$-8,$len
	jnz	.Lcloop8
	pop	%rbx
	cmp	\$0,$len
	jne	.Lcloop1
.Lexit:
	sub	\$1,$XX[0]#b
	movb	$XX[0]#b,-2($dat)
	movb	$YY#b,-1($dat)

	pop	%r13
	pop	%r12
	repret

.align	16
.Lcloop1:
	add	$TX[0]#b,$YY#b
	movzb	($dat,$YY),$TY#d
	movb	$TX[0]#b,($dat,$YY)
	movb	$TY#b,($dat,$XX[0])
	add	$TX[0]#b,$TY#b
	add	\$1,$XX[0]#b
	movzb	($dat,$TY),$TY#d
	movzb	($dat,$XX[0]),$TX[0]#d
	xorb	($inp),$TY#b
	lea	1($inp),$inp
	movb	$TY#b,($out)
	lea	1($out),$out
	sub	\$1,$len
	jnz	.Lcloop1
	jmp	.Lexit
.size	RC4,.-RC4
___

$code =~ s/#([bwd])/$1/gm;

$code =~ s/repret/.byte\t0xF3,0xC3/gm;

print $code;
