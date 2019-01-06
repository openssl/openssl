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

$flavour = shift || "o32";
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

if ($flavour =~ /64|n32/i) {
	$LD="ld";
	$ADDU="daddu";
	$SUBU="dsubu";
	$SRL="dsrl";
	$SLL="dsll";
	$SRA="dsra";
	$BNSZ=8;
} else {
	$LD="lw";
	$ADDU="addu";
	$SUBU="subu";
	$SRL="srl";
	$SLL="sll";
	$SRA="sra";
	$BNSZ=4;
}

$BITS=$BNSZ*8;

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

$code.=<<___;
.text
.set	noat

.align	5
.globl	bn_div_3_words
.ent	bn_div_3_words
bn_div_3_words:
	.set	noreorder
	$LD	$a3,-$BNSZ($a0)		# load R.lo
	$LD	$a4,0($a0)		# load R.hi
	move	$a0,$zero		# Q = 0
	li	$t0,$BITS-1		# loop counter

.Loop:
	sltu	$t1,$a3,$a1		# R - D
	$SUBU	$a6,$a4,$a2
	sltu	$t2,$a4,$a2
	 $ADDU	$a0,$a0			# Q <<= 1
	$SUBU	$a5,$a3,$a1
	sltu	$at,$a6,$t1
	$SUBU	$a6,$a6,$t1
	 or	$a0,1			# set speculative bit
	addu	$t2,$t2,$at
	 $SRL	$a1,$a1,1		# D >>= 1

	$SUBU	$at,$zero,$t2
	xor	$a0,$t2			# flip speculative bit
	 $SLL	$a7,$a2,$BITS-1

	xor	$a3,$a5			# select between R and R - D
	xor	$a4,$a6
	 $SRL	$a2,$a2,1
	and	$a3,$at
	and	$a4,$at
	 or	$a1,$a1,$a7
	xor	$a3,$a5
	xor	$a4,$a6
	bnez	$t0,.Loop
	addiu	$t0,-1

	$SRA	$t0,$a0,$BITS-1		# top bit -> mask

	sltu	$t1,$a3,$a1		# R - D
	$SUBU	$a6,$a4,$a2
	sltu	$t2,$a4,$a2
	 $ADDU	$a0,$a0			# Q <<= 1
	sltu	$at,$a6,$t1
	 or	$a0,1			# set speculative bit
	addu	$t2,$t2,$at
	xor	$a0,$t2			# flip speculative bit

	or	$a0,$a0,$t0		# all ones if overflow
	jr	$ra
	move	$t0,$a0			# harmonize ABIs
.end	bn_div_3_words
___

print $code;
close STDOUT;
