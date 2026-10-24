#! /usr/bin/env perl
# Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# The module is, however, dual licensed under OpenSSL and CRYPTOGAMS
# licenses depending on where you obtain it. For further details see
# https://github.com/dot-asm/cryptogams/.
# ====================================================================
# ChaCha20 for MIPS.
#
# March 2019.
#
# Even though compiler seems to generate optimal rounds loop, same as
# ROUNDs below, it somehow screws up the outer loop...
#
# R1x000	15.5/?		(big-endian)
# Octeon II	9.2(*)/+65%	(little-endian)
#
# (*)	aligned intput and output, result for misaligned is 10.7;
#
######################################################################
# There is a number of MIPS ABI in use, O32 and N32/64 are most
# widely used. Then there is a new contender: NUBI. It appears that if
# one picks the latter, it's possible to arrange code in ABI neutral
# manner. Therefore let's stick to NUBI register layout:
#
($zero,$at,$t0,$t1,$t2)=map("\$$_",(0..2,24,25));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("\$$_",(12..23));
($gp,$tp,$sp,$fp,$ra)=map("\$$_",(3,28..31));
#
# The return value is placed in $a0. Following coding rules facilitate
# interoperability:
#
# - never ever touch $tp, "thread pointer", former $gp;
# - copy return value to $t0, former $v0 [or to $a0 if you're adapting
#   old code];
# - on O32 populate $a4-$a7 with 'lw $aN,4*N($sp)' if necessary;
#
# For reference here is register layout for N32/64 MIPS ABIs:
#
# ($zero,$at,$v0,$v1)=map("\$$_",(0..3));
# ($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
# ($t0,$t1,$t2,$t3,$t8,$t9)=map("\$$_",(12..15,24,25));
# ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7)=map("\$$_",(16..23));
# ($gp,$sp,$fp,$ra)=map("\$$_",(28..31));
#
$flavour = shift || "o32"; # supported flavours are o32,n32,64,nubi32,nubi64

if ($flavour =~ /64|n32/i) {
	$PTR_ADD="daddu";	# incidentally works even on n32
	$PTR_SUB="dsubu";	# incidentally works even on n32
	$REG_S="sd";
	$REG_L="ld";
	$PTR_SLL="dsll";	# incidentally works even on n32
	$SZREG=8;
} else {
	$PTR_ADD="addu";
	$PTR_SUB="subu";
	$REG_S="sw";
	$REG_L="lw";
	$PTR_SLL="sll";
	$SZREG=4;
}

$FRAMESIZE=64+16*$SZREG;
$SAVED_REGS_MASK = ($flavour =~ /nubi/i) ? "0xc0fff008" : "0xc0ff0000";
#
######################################################################

my @x = map("\$$_",(10..25));
my @y = map("\$$_",(2,3,7..9,1,31));
my ($out, $inp, $len, $key, $counter) = ($a0,$a1,$a2,$a3,$a4);

sub ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));

$code.=<<___;
	addu		@x[$a0],@x[$a0],@x[$b0]		# Q0
	 addu		@x[$a1],@x[$a1],@x[$b1]		# Q1
	  addu		@x[$a2],@x[$a2],@x[$b2]		# Q2
	   addu		@x[$a3],@x[$a3],@x[$b3]		# Q3
	xor		@x[$d0],@x[$d0],@x[$a0]
	 xor		@x[$d1],@x[$d1],@x[$a1]
	  xor		@x[$d2],@x[$d2],@x[$a2]
	   xor		@x[$d3],@x[$d3],@x[$a3]
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr		@x[$d0],@x[$d0],16
	 rotr		@x[$d1],@x[$d1],16
	  rotr		@x[$d2],@x[$d2],16
	   rotr		@x[$d3],@x[$d3],16
#else
	srl		@y[0],@x[$d0],16
	 srl		@y[1],@x[$d1],16
	  srl		@y[2],@x[$d2],16
	   srl		@y[3],@x[$d3],16
	sll		@x[$d0],@x[$d0],16
	 sll		@x[$d1],@x[$d1],16
	  sll		@x[$d2],@x[$d2],16
	   sll		@x[$d3],@x[$d3],16
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]
#endif

	addu		@x[$c0],@x[$c0],@x[$d0]
	 addu		@x[$c1],@x[$c1],@x[$d1]
	  addu		@x[$c2],@x[$c2],@x[$d2]
	   addu		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr		@x[$b0],@x[$b0],20
	 rotr		@x[$b1],@x[$b1],20
	  rotr		@x[$b2],@x[$b2],20
	   rotr		@x[$b3],@x[$b3],20
#else
	srl		@y[0],@x[$b0],20
	 srl		@y[1],@x[$b1],20
	  srl		@y[2],@x[$b2],20
	   srl		@y[3],@x[$b3],20
	sll		@x[$b0],@x[$b0],12
	 sll		@x[$b1],@x[$b1],12
	  sll		@x[$b2],@x[$b2],12
	   sll		@x[$b3],@x[$b3],12
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]
#endif

	addu		@x[$a0],@x[$a0],@x[$b0]
	 addu		@x[$a1],@x[$a1],@x[$b1]
	  addu		@x[$a2],@x[$a2],@x[$b2]
	   addu		@x[$a3],@x[$a3],@x[$b3]
	xor		@x[$d0],@x[$d0],@x[$a0]
	 xor		@x[$d1],@x[$d1],@x[$a1]
	  xor		@x[$d2],@x[$d2],@x[$a2]
	   xor		@x[$d3],@x[$d3],@x[$a3]
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr		@x[$d0],@x[$d0],24
	 rotr		@x[$d1],@x[$d1],24
	  rotr		@x[$d2],@x[$d2],24
	   rotr		@x[$d3],@x[$d3],24
#else
	srl		@y[0],@x[$d0],24
	 srl		@y[1],@x[$d1],24
	  srl		@y[2],@x[$d2],24
	   srl		@y[3],@x[$d3],24
	sll		@x[$d0],@x[$d0],8
	 sll		@x[$d1],@x[$d1],8
	  sll		@x[$d2],@x[$d2],8
	   sll		@x[$d3],@x[$d3],8
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]
#endif

	addu		@x[$c0],@x[$c0],@x[$d0]
	 addu		@x[$c1],@x[$c1],@x[$d1]
	  addu		@x[$c2],@x[$c2],@x[$d2]
	   addu		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr		@x[$b0],@x[$b0],25
	 rotr		@x[$b1],@x[$b1],25
	  rotr		@x[$b2],@x[$b2],25
	   rotr		@x[$b3],@x[$b3],25
#else
	srl		@y[0],@x[$b0],25
	 srl		@y[1],@x[$b1],25
	  srl		@y[2],@x[$b2],25
	   srl		@y[3],@x[$b3],25
	sll		@x[$b0],@x[$b0],7
	 sll		@x[$b1],@x[$b1],7
	  sll		@x[$b2],@x[$b2],7
	   sll		@x[$b3],@x[$b3],7
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]
#endif
___
}

$code.=<<___;
# if (defined(__mips_smartmips) || defined(_MIPS_ARCH_MIPS32R3) || \\
      defined(_MIPS_ARCH_MIPS32R5) || defined(_MIPS_ARCH_MIPS32R6)) \\
      && !defined(_MIPS_ARCH_MIPS32R2)
#  define _MIPS_ARCH_MIPS32R2
# endif

# if (defined(_MIPS_ARCH_MIPS64R3) || defined(_MIPS_ARCH_MIPS64R5) || \\
      defined(_MIPS_ARCH_MIPS64R6)) \\
      && !defined(_MIPS_ARCH_MIPS64R2)
#  define _MIPS_ARCH_MIPS64R2
# endif

#if defined(__MIPSEB__) && !defined(MIPSEB)
# define MIPSEB
#endif

.text

.set	noat
.set	reorder

.align	5
.ent	__ChaCha
__ChaCha:
	.frame	$sp,0,$ra
	.mask	0,0
	.set	reorder
	lw		@x[0], 4*0($sp)
	lw		@x[1], 4*1($sp)
	lw		@x[2], 4*2($sp)
	lw		@x[3], 4*3($sp)
	lw		@x[4], 4*4($sp)
	lw		@x[5], 4*5($sp)
	lw		@x[6], 4*6($sp)
	lw		@x[7], 4*7($sp)
	lw		@x[8], 4*8($sp)
	lw		@x[9], 4*9($sp)
	lw		@x[10],4*10($sp)
	lw		@x[11],4*11($sp)
	move		@x[12],$fp
	lw		@x[13],4*13($sp)
	lw		@x[14],4*14($sp)
	lw		@x[15],4*15($sp)
.Lalt_entry:
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	move		@y[0],@x[0]
	move		@y[1],@x[1]
	move		@y[2],@x[2]
	move		@y[3],@x[3]
#endif
.Loop:
___
	&ROUND(0, 4, 8, 12);
	&ROUND(0, 5, 10, 15);
$code.=<<___;
	.set		noreorder
	bnez		$at,.Loop
	subu		$at,$at,1
	.set		reorder

#if !defined(_MIPS_ARCH_MIPS32R2) && !defined(_MIPS_ARCH_MIPS64R2)
	lw		@y[0], 4*0($sp)
	lw		@y[1], 4*1($sp)
	lw		@y[2], 4*2($sp)
	lw		@y[3], 4*3($sp)
#endif
	addu		@x[0],@x[0],@y[0]
	lw		@y[0],4*4($sp)
	addu		@x[1],@x[1],@y[1]
	lw		@y[1],4*5($sp)
	addu		@x[2],@x[2],@y[2]
	lw		@y[2],4*6($sp)
	addu		@x[3],@x[3],@y[3]
	lw		@y[3],4*7($sp)
	addu		@x[4],@x[4],@y[0]
	lw		@y[0],4*8($sp)
	addu		@x[5],@x[5],@y[1]
	lw		@y[1], 4*9($sp)
	addu		@x[6],@x[6],@y[2]
	lw		@y[2],4*10($sp)
	addu		@x[7],@x[7],@y[3]
	lw		@y[3],4*11($sp)
	addu		@x[8],@x[8],@y[0]
	#lw		@y[0],4*12($sp)
	addu		@x[9],@x[9],@y[1]
	lw		@y[1],4*13($sp)
	addu		@x[10],@x[10],@y[2]
	lw		@y[2],4*14($sp)
	addu		@x[11],@x[11],@y[3]
	lw		@y[3],4*15($sp)
	addu		@x[12],@x[12],$fp
	addu		@x[13],@x[13],@y[1]
	addu		@x[14],@x[14],@y[2]
	addu		@x[15],@x[15],@y[3]
	jr		$ra
.end	__ChaCha

.globl	ChaCha20_ctr32
.align	5
.ent	ChaCha20_ctr32
ChaCha20_ctr32:
	.frame	$sp,$FRAMESIZE,$ra
	.mask	$SAVED_REGS_MASK,-$SZREG
	.set	noreorder
	$PTR_SUB	$sp,$sp,$FRAMESIZE
	$REG_S		$ra, ($FRAMESIZE-1*$SZREG)($sp)
	$REG_S		$fp, ($FRAMESIZE-2*$SZREG)($sp)
	$REG_S		$s11,($FRAMESIZE-3*$SZREG)($sp)
	$REG_S		$s10,($FRAMESIZE-4*$SZREG)($sp)
	$REG_S		$s9, ($FRAMESIZE-5*$SZREG)($sp)
	$REG_S		$s8, ($FRAMESIZE-6*$SZREG)($sp)
	$REG_S		$s7, ($FRAMESIZE-7*$SZREG)($sp)
	$REG_S		$s6, ($FRAMESIZE-8*$SZREG)($sp)
	$REG_S		$s5, ($FRAMESIZE-9*$SZREG)($sp)
	$REG_S		$s4, ($FRAMESIZE-10*$SZREG)($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);	# optimize non-nubi prologue
	$REG_S		$s3, ($FRAMESIZE-11*$SZREG)($sp)
	$REG_S		$s2, ($FRAMESIZE-12*$SZREG)($sp)
	$REG_S		$s1, ($FRAMESIZE-13*$SZREG)($sp)
	$REG_S		$s0, ($FRAMESIZE-14*$SZREG)($sp)
	$REG_S		$gp, ($FRAMESIZE-15*$SZREG)($sp)
___
$code.=<<___ if ($flavour =~ /o32/i);
	lw		$a4,($FRAMESIZE+4*4)($sp)
___
$code.=<<___;
	.set	reorder

	lui		@x[0],0x6170		# compose sigma
	lui		@x[1],0x3320
	lui		@x[2],0x7962
	lui		@x[3],0x6b20
	ori		@x[0],@x[0],0x7865
	ori		@x[1],@x[1],0x646e
	ori		@x[2],@x[2],0x2d32
	ori		@x[3],@x[3],0x6574

	lw		@x[4], 4*0($key)
	lw		@x[5], 4*1($key)
	lw		@x[6], 4*2($key)
	lw		@x[7], 4*3($key)
	lw		@x[8], 4*4($key)
	lw		@x[9], 4*5($key)
	lw		@x[10],4*6($key)
	lw		@x[11],4*7($key)

	lw		@x[12],4*0($counter)
	lw		@x[13],4*1($counter)
	lw		@x[14],4*2($counter)
	lw		@x[15],4*3($counter)

	sw		@x[0], 4*0($sp)
	sw		@x[1], 4*1($sp)
	sw		@x[2], 4*2($sp)
	sw		@x[3], 4*3($sp)
	sw		@x[4], 4*4($sp)
	sw		@x[5], 4*5($sp)
	sw		@x[6], 4*6($sp)
	sw		@x[7], 4*7($sp)
	sw		@x[8], 4*8($sp)
	sw		@x[9], 4*9($sp)
	sw		@x[10],4*10($sp)
	sw		@x[11],4*11($sp)
	move		$fp,@x[12]
	sw		@x[13],4*13($sp)
	sw		@x[14],4*14($sp)
	sw		@x[15],4*15($sp)

	li		$at,9
	bal		.Lalt_entry

	sltiu		$at,$len,64
	or		$ra,$inp,$out
	andi		$ra,$ra,3		# both are aligned?
	bnez		$at,.Ltail

#ifndef	MIPSEB
	beqz		$ra,.Loop_aligned
#endif
.Loop_misaligned:
	# On little-endian pre-R6 processor it's possible to reduce
	# amount of instructions by using lwl+lwr to load input, and
	# single 'xor' per word. Judging from sheer instruction count
	# it could give ~15% improvement. But in real life it turned
	# to be just ~5%, too little to care about...

	lbu		@y[0],0($inp)
	lbu		@y[1],1($inp)
	srl		@y[4],@x[0],8
	lbu		@y[2],2($inp)
	srl		@y[5],@x[0],16
	lbu		@y[3],3($inp)
	srl		@y[6],@x[0],24
___
for(my $i=0; $i<15; $i++) {
my $j=4*$i;
my $k=4*($i+1);
$code.=<<___;
	xor		@x[$i],@x[$i],@y[0]
	lbu		@y[0],$k+0($inp)
	xor		@y[4],@y[4],@y[1]
	lbu		@y[1],$k+1($inp)
	xor		@y[5],@y[5],@y[2]
	lbu		@y[2],$k+2($inp)
	xor		@y[6],@y[6],@y[3]
	lbu		@y[3],$k+3($inp)
	sb		@x[$i],$j+0($out)
	sb		@y[4],$j+1($out)
	srl		@y[4],@x[$i+1],8
	sb		@y[5],$j+2($out)
	srl		@y[5],@x[$i+1],16
	sb		@y[6],$j+3($out)
	srl		@y[6],@x[$i+1],24
___
}
$code.=<<___;
	xor		@x[15],@x[15],@y[0]
	xor		@y[4],@y[4],@y[1]
	xor		@y[5],@y[5],@y[2]
	xor		@y[6],@y[6],@y[3]
	sb		@x[15],60($out)
	addu		$fp,$fp,1		# next counter value
	sb		@y[4],61($out)
	$PTR_SUB	$len,$len,64
	sb		@y[5],62($out)
	$PTR_ADD	$inp,$inp,64
	sb		@y[6],63($out)
	$PTR_ADD	$out,$out,64
	beqz		$len,.Ldone

	sltiu		@y[4],$len,64
	li		$at,9
	bal		__ChaCha

	beqz		@y[4],.Loop_misaligned

#ifndef	MIPSEB
	b		.Ltail

.align	4
.Loop_aligned:
	lw		@y[0],0($inp)
	lw		@y[1],4($inp)
	lw		@y[2],8($inp)
	lw		@y[3],12($inp)
___
for (my $i=0; $i<12; $i+=4) {
my $j = 4*$i;
my $k = 4*($i+4);
$code.=<<___;
	xor		@x[$i+0],@x[$i+0],@y[0]
	lw		@y[0],$k+0($inp)
	xor		@x[$i+1],@x[$i+1],@y[1]
	lw		@y[1],$k+4($inp)
	xor		@x[$i+2],@x[$i+2],@y[2]
	lw		@y[2],$k+8($inp)
	xor		@x[$i+3],@x[$i+3],@y[3]
	lw		@y[3],$k+12($inp)
	sw		@x[$i+0],$j+0($out)
	sw		@x[$i+1],$j+4($out)
	sw		@x[$i+2],$j+8($out)
	sw		@x[$i+3],$j+12($out)
___
}
$code.=<<___;
	xor		@x[12],@x[12],@y[0]
	xor		@x[13],@x[13],@y[1]
	xor		@x[14],@x[14],@y[2]
	xor		@x[15],@x[15],@y[3]
	sw		@x[12],48($out)
	addu		$fp,$fp,1		# next counter value
	sw		@x[13],52($out)
	$PTR_SUB	$len,$len,64
	sw		@x[14],56($out)
	$PTR_ADD	$inp,$inp,64
	sw		@x[15],60($out)
	$PTR_ADD	$out,$out,64
	sltiu		@y[4],$len,64
	beqz		$len,.Ldone

	li		$at,9
	bal		__ChaCha

	beqz		@y[4],.Loop_aligned
#endif
.Ltail:
	move		$fp,$sp
	sw		@x[1], 4*1($sp)
	sw		@x[2], 4*2($sp)
	sw		@x[3], 4*3($sp)
	sw		@x[4], 4*4($sp)
	sw		@x[5], 4*5($sp)
	sw		@x[6], 4*6($sp)
	sw		@x[7], 4*7($sp)
	sw		@x[8], 4*8($sp)
	sw		@x[9], 4*9($sp)
	sw		@x[10],4*10($sp)
	sw		@x[11],4*11($sp)
	sw		@x[12],4*12($sp)
	sw		@x[13],4*13($sp)
	sw		@x[14],4*14($sp)
	sw		@x[15],4*15($sp)

.Loop_tail:
	sltiu		$at,$len,4
	$PTR_ADD	$fp,$fp,4
	bnez		$at,.Last_word

	lbu		@y[0],0($inp)
	lbu		@y[1],1($inp)
	lbu		@y[2],2($inp)
	$PTR_SUB	$len,$len,4
	lbu		@y[3],3($inp)
	$PTR_ADD	$inp,$inp,4
	xor		@y[0],@y[0],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[1],@y[1],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[2],@y[2],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[3],@y[3],@x[0]
	lw		@x[0],0($fp)
	sb		@y[0],0($out)
	sb		@y[1],1($out)
	sb		@y[2],2($out)
	sb		@y[3],3($out)
	$PTR_ADD	$out,$out,4
	b		.Loop_tail

	.set	noreorder
.Last_word:
	beqz		$len,.Ldone
	$PTR_SUB	$len,$len,1
	lbu		@y[0],0($inp)
	$PTR_ADD	$inp,$inp,1
	xor		@y[0],@y[0],@x[0]
	srl		@x[0],@x[0],8
	sb		@y[0],0($out)
	b		.Last_word
	$PTR_ADD	$out,$out,1

.align	4
.Ldone:
	$REG_L		$ra, ($FRAMESIZE-1*$SZREG)($sp)
	$REG_L		$fp, ($FRAMESIZE-2*$SZREG)($sp)
	$REG_L		$s11,($FRAMESIZE-3*$SZREG)($sp)
	$REG_L		$s10,($FRAMESIZE-4*$SZREG)($sp)
	$REG_L		$s9, ($FRAMESIZE-5*$SZREG)($sp)
	$REG_L		$s8, ($FRAMESIZE-6*$SZREG)($sp)
	$REG_L		$s7, ($FRAMESIZE-7*$SZREG)($sp)
	$REG_L		$s6, ($FRAMESIZE-8*$SZREG)($sp)
	$REG_L		$s5, ($FRAMESIZE-9*$SZREG)($sp)
	$REG_L		$s4, ($FRAMESIZE-10*$SZREG)($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);
	$REG_L		$s3, ($FRAMESIZE-11*$SZREG)($sp)
	$REG_L		$s2, ($FRAMESIZE-12*$SZREG)($sp)
	$REG_L		$s1, ($FRAMESIZE-13*$SZREG)($sp)
	$REG_L		$s0, ($FRAMESIZE-14*$SZREG)($sp)
	$REG_L		$gp, ($FRAMESIZE-15*$SZREG)($sp)
___
$code.=<<___;
	jr		$ra
	$PTR_ADD	$sp,$sp,$FRAMESIZE
.end	ChaCha20_ctr32
___

$output=pop and open STDOUT,">$output";
print $code;
close STDOUT;
