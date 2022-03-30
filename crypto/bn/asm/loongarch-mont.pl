#! /usr/bin/env perl
# Copyright 2010-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Song Ding <songding@loongson.cn> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# December 2021
#
# This module doesn't present direct interest for OpenSSL, because it
# doesn't provide better performance for longer keys, at least not on
# in-order-execution cores. While 512-bit RSA sign operations can be
# 65.7% faster in 64-bit mode, 1024-bit ones are 24.6% faster, and
# 2048-bit ones are only 10.4% faster, the code improve rsa512 *verify*
# benchmark by 20.4%, rsa1024 one - by 10.9%:-)
# All comparisons are against bn_mul_mont-free assembler.

######################################################################
# Here is register layout for LOONGARCH ABIs.
# The return value is placed in $v0($a0).

($zero,$ra,$tp,$sp,$fp)=map("\$r$_",(0..3,22));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$r$_",(4..11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8)=map("\$r$_",(12..20));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$r$_",(23..31));


$PTR_ADD="addi.d";
$REG_S="st.d";
$REG_L="ld.d";
$SZREG=8;

######################################################################

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$LD="ld.d";
$ST="st.d";
$MULD="mul.d";
$MULHD="mulh.du";
$ADDU="add.d";
$SUBU="sub.d";
$BNSZ=8;

# int bn_mul_mont(
$rp=$a0;	# BN_ULONG *rp,
$ap=$a1;	# const BN_ULONG *ap,
$bp=$a2;	# const BN_ULONG *bp,
$np=$a3;	# const BN_ULONG *np,
$n0=$a4;	# const BN_ULONG *n0,
$num=$a5;	# int num);

$lo0=$a6;
$hi0=$a7;
$lo1=$t1;
$hi1=$t2;
$aj=$t3;
$bi=$t4;
$nj=$t5;
$tp=$t6;
$alo=$t7;
$ahi=$s0;
$nlo=$s1;
$nhi=$s2;
$tj=$s3;
$i=$s4;
$j=$s5;
$m1=$s6;

$code=<<___;
.text
.align  5	
.globl	bn_mul_mont
bn_mul_mont:
___
$code.=<<___;
	slti	$t8,$num,4
	li.d	$t0,0
	bnez	$t8,1f
	slti	$t8,$num,17	
	bnez	$t8,bn_mul_mont_internal
1:	li.d  $a0,0
    jr	$ra

.align	5
bn_mul_mont_internal:
    addi.d  $sp,$sp,-64
    $REG_S  $fp,$sp,$SZREG*0
    $REG_S  $s0,$sp,$SZREG*1
    $REG_S  $s1,$sp,$SZREG*2
    $REG_S  $s2,$sp,$SZREG*3
    $REG_S  $s3,$sp,$SZREG*4
    $REG_S  $s4,$sp,$SZREG*5
    $REG_S  $s5,$sp,$SZREG*6
    $REG_S  $s6,$sp,$SZREG*7
___
$code.=<<___;
    move    $fp,$sp
	$LD     $n0,$n0,0
	$LD     $bi,$bp,0	# bp[0]
	$LD     $aj,$ap,0	# ap[0]
	$LD     $nj,$np,0	# np[0]

    $PTR_ADD    $sp,$sp,-2*$BNSZ	# place for two extra words
	slli.d  $num,$num,`log($BNSZ)/log(2)`
	li.d	$t8,-4096
    $SUBU   $sp,$sp,$num
	and     $sp,$sp,$t8

	$LD     $ahi,$ap,$BNSZ
	$LD     $nhi,$np,$BNSZ
	$MULD	$lo0,$aj,$bi
	$MULHD	$hi0,$aj,$bi
	$MULD	$m1,$lo0,$n0

	$MULD	$alo,$ahi,$bi
	$MULHD	$ahi,$ahi,$bi

	$MULD	$lo1,$nj,$m1
	$MULHD	$hi1,$nj,$m1
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	$MULD	$nlo,$nhi,$m1
	$MULHD	$nhi,$nhi,$m1

	move	$tp,$sp
	li.d	$j,2*$BNSZ
.align	4
.L1st:
	$ADDU   $aj,$ap,$j
	$ADDU   $nj,$np,$j
	$LD     $aj,$aj,0
	$LD     $nj,$nj,0

	$ADDU	$lo0,$alo,$hi0
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo0,$hi0
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$hi1,$nhi,$t0
	$MULD	$alo,$aj,$bi
	$MULHD	$ahi,$aj,$bi

	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	addi.d	$j,$j,$BNSZ
	$ST     $lo1,$tp,0
	sltu	$t0,$j,$num
	$MULD	$nlo,$nj,$m1
	$MULHD	$nhi,$nj,$m1

	$PTR_ADD $tp,$tp,$BNSZ
	bnez	$t0,.L1st

	$ADDU	$lo0,$alo,$hi0
	sltu	$t8,$lo0,$hi0
	$ADDU	$hi0,$ahi,$t8

	$ADDU	$lo1,$nlo,$hi1
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi1,$nhi,$t0
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8

	$ST     $lo1,$tp,0

	$ADDU	$hi1,$hi1,$hi0
	sltu	$t8,$hi1,$hi0
	$ST     $hi1,$tp,$BNSZ
	$ST     $t8,$tp,2*$BNSZ

	li.d	$i,$BNSZ
.align	4
.Louter:
	$ADDU   $bi,$bp,$i
	$LD     $bi,$bi,0
	$LD     $aj,$ap,0
	$LD     $ahi,$ap,$BNSZ
	$LD     $tj,$sp,0

	$LD     $nj,$np,0
	$LD     $nhi,$np,$BNSZ
	$MULD	$lo0,$aj,$bi
	$MULHD	$hi0,$aj,$bi
	$ADDU	$lo0,$lo0,$tj
	sltu	$t8,$lo0,$tj
	$ADDU	$hi0,$hi0,$t8
	$MULD	$m1,$lo0,$n0

	$MULD	$alo,$ahi,$bi
	$MULHD	$ahi,$ahi,$bi

	$MULD	$lo1,$nj,$m1
	$MULHD	$hi1,$nj,$m1

	$ADDU	$lo1,$lo1,$lo0
	sltu	$t8,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t8
	$MULD	$nlo,$nhi,$m1
	$MULHD	$nhi,$nhi,$m1

	move	$tp,$sp
	li.d	$j,2*$BNSZ
	$LD     $tj,$tp,$BNSZ
.align	4
.Linner:
	$ADDU   $aj,$ap,$j
	$ADDU   $nj,$np,$j
	$LD     $aj,$aj,0
	$LD     $nj,$nj,0

	$ADDU	$lo0,$alo,$hi0
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo0,$hi0
	sltu	$t0,$lo1,$hi1
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$hi1,$nhi,$t0
	$MULD	$alo,$aj,$bi
	$MULHD	$ahi,$aj,$bi

	$ADDU	$lo0,$lo0,$tj
	addi.d	$j,$j,$BNSZ
	sltu	$t8,$lo0,$tj
	$ADDU	$lo1,$lo1,$lo0
	$ADDU	$hi0,$hi0,$t8
	sltu	$t0,$lo1,$lo0
	$LD	$tj,$tp,2*$BNSZ
	$ADDU	$hi1,$hi1,$t0
	sltu	$t8,$j,$num
	$MULD	$nlo,$nj,$m1
	$MULHD	$nhi,$nj,$m1
	$ST     $lo1,$tp,0
	$PTR_ADD $tp,$tp,$BNSZ
	bnez	$t8,.Linner

	$ADDU	$lo0,$alo,$hi0
	sltu	$t8,$lo0,$hi0
	$ADDU	$hi0,$ahi,$t8
	$ADDU	$lo0,$lo0,$tj
	sltu	$t0,$lo0,$tj
	$ADDU	$hi0,$hi0,$t0

	$LD     $tj,$tp,2*$BNSZ
	$ADDU	$lo1,$nlo,$hi1
	sltu	$t8,$lo1,$hi1
	$ADDU	$hi1,$nhi,$t8
	$ADDU	$lo1,$lo1,$lo0
	sltu	$t0,$lo1,$lo0
	$ADDU	$hi1,$hi1,$t0
	$ST     $lo1,$tp,0

	$ADDU	$lo1,$hi1,$hi0
	sltu	$hi1,$lo1,$hi0
	$ADDU	$lo1,$lo1,$tj
	sltu	$t8,$lo1,$tj
	$ADDU	$hi1,$hi1,$t8
	$ST     $lo1,$tp,$BNSZ
	$ST	$hi1,$tp,2*$BNSZ

	$PTR_ADD $i,$i,$BNSZ
	sltu	$t0,$i,$num
	bnez	$t0,.Louter

	$ADDU   $tj,$sp,$num	# &tp[num]
	move	$tp,$sp
	move	$ap,$sp
	li.d	$hi0,0		# clear borrow bit

.align	4
.Lsub:	
	$LD     $lo0,$tp,0
	$LD     $lo1,$np,0
	$PTR_ADD $tp,$tp,$BNSZ
	$PTR_ADD $np,$np,$BNSZ
	$SUBU	$lo1,$lo0,$lo1	# tp[i]-np[i]
	sltu	$t8,$lo0,$lo1
	$SUBU	$lo0,$lo1,$hi0
	sltu	$hi0,$lo1,$lo0
	$ST     $lo0,$rp,0
	or      $hi0,$hi0,$t8
	sltu	$t8,$tp,$tj
	$PTR_ADD $rp,$rp,$BNSZ
	bnez	$t8,.Lsub
	$SUBU	$hi0,$hi1,$hi0	# handle upmost overflow bit
	move	$tp,$sp
	$SUBU   $rp,$rp,$num	# restore rp
	nor     $hi1,$hi0,$zero
.Lcopy:	
	$LD     $nj,$tp,0	# conditional move
	$LD	    $aj,$rp,0
    	$ST	    $zero,$tp,0
	$PTR_ADD $tp,$tp,$BNSZ
	and	    $nj,$nj,$hi0
	and	    $aj,$aj,$hi1
	or	    $aj,$aj,$nj
	sltu	$t8,$tp,$tj
	$ST	    $aj,$rp,0
	$PTR_ADD $rp,$rp,$BNSZ
	bnez	$t8,.Lcopy
	li.d	$a0,1
	li.d	$t0,1
    	move    $sp,$fp
___
$code.=<<___;
	$REG_L  $fp,$sp,$SZREG*0
	$REG_L  $s0,$sp,$SZREG*1
    	$REG_L  $s1,$sp,$SZREG*2
    	$REG_L  $s2,$sp,$SZREG*3
    	$REG_L  $s3,$sp,$SZREG*4
    	$REG_L  $s4,$sp,$SZREG*5
    	$REG_L  $s5,$sp,$SZREG*6
    	$REG_L  $s6,$sp,$SZREG*7
   	$PTR_ADD $sp,$sp,64;
	jr	$ra
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;
close STDOUT;
