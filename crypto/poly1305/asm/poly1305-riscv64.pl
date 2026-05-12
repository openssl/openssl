#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Poly1305 hash for RISC-V.
#
# February 2019
#
# In the essence it's pretty straightforward transliteration of MIPS
# module [without big-endian option].
#
# 1.8 cycles per byte on U74, >100% faster than compiler-generated
# code. 1.9 cpb on C910, ~75% improvement. 3.3 on Spacemit X60, ~69%
# improvement.
#
# July 2025.
#
# Add vector implementation. It works with arbitrarily wide vector
# units, but doesn't utilize more than 2048 bits. Spacemit X60 has
# 256-bit unit and achieves 1.2 cpb for aligned data.
#
######################################################################
#
($zero,$ra,$sp,$gp,$tp)=map("x$_",(0..4));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7,28..31));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
#
######################################################################

use FindBin qw($Bin);
use lib "$Bin/../../perlasm";
use riscv;

$flavour = shift || "64";

my $use_v = 0;
if ($flavour =~ /^v$/) {
    $use_v = 1;
    $flavour = shift || "64";
}

for (@ARGV) {   $output=$_ if (/\w[\w\-]*\.\w+$/);   }
open STDOUT,">$output";


if ($flavour =~ /64/) {{{
######################################################################
# 64-bit code path...
#
my ($ctx,$inp,$len,$padbit) = ($a0,$a1,$a2,$a3);
my ($in0,$in1,$tmp0,$tmp1,$tmp2,$tmp3,$tmp4) = ($a4,$a5,$a6,$a7,$t0,$t1,$t2);

$code.=<<___;
#if __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif

.option	pic
.text
___

unless ($use_v) {
$code.=<<___;

.globl	poly1305_init_riscv64
.type	poly1305_init_riscv64,\@function
.align	2
poly1305_init_riscv64:
	sd	$zero,0($ctx)
	sd	$zero,8($ctx)
	sd	$zero,16($ctx)

	beqz	$inp,.Lno_key

	andi	$tmp0,$inp,7		# $inp % 8
	andi	$inp,$inp,-8		# align $inp
	slli	$tmp0,$tmp0,3		# byte to bit offset
	ld	$in0,0($inp)
	ld	$in1,8($inp)
	beqz	$tmp0,.Laligned_key

	ld	$tmp2,16($inp)
	neg	$tmp1,$tmp0		# implicit &63 in sll
	srl	$in0,$in0,$tmp0
	sll	$tmp3,$in1,$tmp1
	srl	$in1,$in1,$tmp0
	sll	$tmp2,$tmp2,$tmp1
	or	$in0,$in0,$tmp3
	or	$in1,$in1,$tmp2

.Laligned_key:
	li	$tmp0,1
	slli	$tmp0,$tmp0,32		# 0x0000000100000000
	addi	$tmp0,$tmp0,-63		# 0x00000000ffffffc1
	slli	$tmp0,$tmp0,28		# 0x0ffffffc10000000
	addi	$tmp0,$tmp0,-1		# 0x0ffffffc0fffffff

	and	$in0,$in0,$tmp0
	addi	$tmp0,$tmp0,-3		# 0x0ffffffc0ffffffc
	and	$in1,$in1,$tmp0

	sd	$in0,24($ctx)
	srli	$tmp0,$in1,2
	sd	$in1,32($ctx)
	add	$tmp0,$tmp0,$in1	# s1 = r1 + (r1 >> 2)
	sd	$tmp0,40($ctx)
	sw	$zero,48($ctx)		# top_power

.Lno_key:
	li	$a0,0			# return 0
	ret
.size	poly1305_init_riscv64,.-poly1305_init_riscv64
___
{
my ($h0,$h1,$h2,$r0,$r1,$rs1,$d0,$d1,$d2) =
   ($s0,$s1,$s2,$s3,$t3,$t4,$in0,$in1,$t2);
my ($shr,$shl) = ($t5,$t6);		# used on R6

$code.=<<___;
.globl	poly1305_blocks
.type	poly1305_blocks,\@function
.align	2
poly1305_blocks:
	andi	$len,$len,-16		# complete blocks only
	beqz	$len,.Lno_data

	caddi	$sp,$sp,-4*__SIZEOF_POINTER__
	PUSH	$s0,3*__SIZEOF_POINTER__($sp)
	PUSH	$s1,2*__SIZEOF_POINTER__($sp)
	PUSH	$s2,1*__SIZEOF_POINTER__($sp)
	PUSH	$s3,0*__SIZEOF_POINTER__($sp)

	andi	$shr,$inp,7
	andi	$inp,$inp,-8		# align $inp
	slli	$shr,$shr,3		# byte to bit offset
	neg	$shl,$shr		# implicit &63 in sll

	ld	$h0,0($ctx)		# load hash value
	ld	$h1,8($ctx)
	ld	$h2,16($ctx)

	ld	$r0,24($ctx)		# load key
	ld	$r1,32($ctx)
	ld	$rs1,40($ctx)

	add	$len,$len,$inp		# end of buffer

.Loop:
	ld	$in0,0($inp)		# load input
	ld	$in1,8($inp)
	beqz	$shr,.Laligned_inp

	ld	$tmp2,16($inp)
	srl	$in0,$in0,$shr
	sll	$tmp3,$in1,$shl
	srl	$in1,$in1,$shr
	sll	$tmp2,$tmp2,$shl
	or	$in0,$in0,$tmp3
	or	$in1,$in1,$tmp2

.Laligned_inp:
	caddi	$inp,$inp,16

	andi	$tmp0,$h2,-4		# modulo-scheduled reduction
	srli	$tmp1,$h2,2
	andi	$h2,$h2,3

	add	$d0,$h0,$in0		# accumulate input
	 add	$tmp1,$tmp1,$tmp0
	sltu	$tmp0,$d0,$h0
	add	$d0,$d0,$tmp1		# ... and residue
	sltu	$tmp1,$d0,$tmp1
	add	$d1,$h1,$in1
	add	$tmp0,$tmp0,$tmp1
	sltu	$tmp1,$d1,$h1
	add	$d1,$d1,$tmp0

	 add	$d2,$h2,$padbit
	 sltu	$tmp0,$d1,$tmp0
	mulhu	$h1,$r0,$d0		# h0*r0
	mul	$h0,$r0,$d0

	 add	$d2,$d2,$tmp1
	 add	$d2,$d2,$tmp0
	mulhu	$tmp1,$rs1,$d1		# h1*5*r1
	mul	$tmp0,$rs1,$d1

	mulhu	$h2,$r1,$d0		# h0*r1
	mul	$tmp2,$r1,$d0
	 add	$h0,$h0,$tmp0
	 add	$h1,$h1,$tmp1
	 sltu	$tmp0,$h0,$tmp0

	 add	$h1,$h1,$tmp0
	 add	$h1,$h1,$tmp2
	mulhu	$tmp1,$r0,$d1		# h1*r0
	mul	$tmp0,$r0,$d1

	 sltu	$tmp2,$h1,$tmp2
	 add	$h2,$h2,$tmp2
	mul	$tmp2,$rs1,$d2		# h2*5*r1

	 add	$h1,$h1,$tmp0
	 add	$h2,$h2,$tmp1
	mul	$tmp3,$r0,$d2		# h2*r0
	 sltu	$tmp0,$h1,$tmp0
	 add	$h2,$h2,$tmp0

	add	$h1,$h1,$tmp2
	sltu	$tmp2,$h1,$tmp2
	add	$h2,$h2,$tmp2
	add	$h2,$h2,$tmp3

	bne	$inp,$len,.Loop

	sd	$h0,0($ctx)		# store hash value
	sd	$h1,8($ctx)
	sd	$h2,16($ctx)

	POP	$s0,3*__SIZEOF_POINTER__($sp)		# epilogue
	POP	$s1,2*__SIZEOF_POINTER__($sp)
	POP	$s2,1*__SIZEOF_POINTER__($sp)
	POP	$s3,0*__SIZEOF_POINTER__($sp)
	caddi	$sp,$sp,4*__SIZEOF_POINTER__

.Lno_data:
	ret
.size	poly1305_blocks,.-poly1305_blocks
___
}
{
my ($ctx,$mac,$nonce) = ($a0,$a1,$a2);

$code.=<<___;
.globl	poly1305_emit
.type	poly1305_emit,\@function
.align	2
poly1305_emit:
	ld	$tmp2,16($ctx)
	ld	$tmp0,0($ctx)
	ld	$tmp1,8($ctx)

	andi	$in0,$tmp2,-4		# final reduction
	srl	$in1,$tmp2,2
	andi	$tmp2,$tmp2,3
	add	$in0,$in0,$in1

	add	$tmp0,$tmp0,$in0
	sltu	$in1,$tmp0,$in0
	 addi	$in0,$tmp0,5		# compare to modulus
	add	$tmp1,$tmp1,$in1
	 sltiu	$tmp3,$in0,5
	sltu	$tmp4,$tmp1,$in1
	 add	$in1,$tmp1,$tmp3
	add	$tmp2,$tmp2,$tmp4
	 sltu	$tmp3,$in1,$tmp3
	 add	$tmp2,$tmp2,$tmp3

	srli	$tmp2,$tmp2,2		# see if it carried/borrowed
	neg	$tmp2,$tmp2

	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1
	and	$in0,$in0,$tmp2
	and	$in1,$in1,$tmp2
	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1

	lwu	$tmp0,0($nonce)		# load nonce
	lwu	$tmp1,4($nonce)
	lwu	$tmp2,8($nonce)
	lwu	$tmp3,12($nonce)
	slli	$tmp1,$tmp1,32
	slli	$tmp3,$tmp3,32
	or	$tmp0,$tmp0,$tmp1
	or	$tmp2,$tmp2,$tmp3

	add	$in0,$in0,$tmp0		# accumulate nonce
	add	$in1,$in1,$tmp2
	sltu	$tmp0,$in0,$tmp0
	add	$in1,$in1,$tmp0

	andi	$tmp0,$mac,7		# check $mac alignment
	bnez	$tmp0,.Lemit_misaligned

	sd	$in0,0($mac)		# write mac value (aligned)
	sd	$in1,8($mac)
	j	.Lemit_done

.Lemit_misaligned:
	srli	$tmp0,$in0,8		# write mac value (byte-by-byte)
	srli	$tmp1,$in0,16
	srli	$tmp2,$in0,24
	sb	$in0,0($mac)
	srli	$tmp3,$in0,32
	sb	$tmp0,1($mac)
	srli	$tmp0,$in0,40
	sb	$tmp1,2($mac)
	srli	$tmp1,$in0,48
	sb	$tmp2,3($mac)
	srli	$tmp2,$in0,56
	sb	$tmp3,4($mac)
	srli	$tmp3,$in1,8
	sb	$tmp0,5($mac)
	srli	$tmp0,$in1,16
	sb	$tmp1,6($mac)
	srli	$tmp1,$in1,24
	sb	$tmp2,7($mac)

	sb	$in1,8($mac)
	srli	$tmp2,$in1,32
	sb	$tmp3,9($mac)
	srli	$tmp3,$in1,40
	sb	$tmp0,10($mac)
	srli	$tmp0,$in1,48
	sb	$tmp1,11($mac)
	srli	$tmp1,$in1,56
	sb	$tmp2,12($mac)
	sb	$tmp3,13($mac)
	sb	$tmp0,14($mac)
	sb	$tmp1,15($mac)

.Lemit_done:

	ret
.size	poly1305_emit,.-poly1305_emit
.string	"Poly1305 for RISC-V, CRYPTOGAMS by \@dot-asm"
___
} # end emit block
} # end unless ($use_v)

if ($use_v) {
########################################################################
# Context layout, same size as other vector poly1305 modules.
#
#	unsigned __int64 h[3];		# current hash value base 2^64
#	unsigned __int64 r[3];		# key value base 2^64
#	unsigned __int32 top_power;
#	struct { unsigned __int32 r^64, r^32, r^16, r^8, r^4, r^2, r; } r[5];

my ($INlo_0,$INlo_1,$INlo_2,$INlo_3,
    $INhi_0,$INhi_1,$INhi_2,$INhi_3,$INhi_4,$INlo_4,
    $H0,$H1,$H2,$H3,$H4, $ACC0,$ACC1,$ACC2,$ACC3,$ACC4) =
    map("v$_", (0..19));
my ($R21_0,$R21_1,$R21_2,$R21_3,$R21_4,$R21_1x5,$R21_2x5,$R21_3x5,$R21_4x5) =
    map("v$_", (20..28));
my ($T0,$T1,$T2) = map("v$_", (29..31));

my ($r4_0,$r4_1,$r4_2,$r4_3,$r4_4,$r4_1x5,$r4_2x5,$r4_3x5,$r4_4x5,
    $r8_0,$r8_1,$r8_2,$r8_3,$r8_4,$r8_1x5,$r8_2x5,$r8_3x5,$r8_4x5) =
   ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,
    $a4,$a5,$a6,$a7,$t2,$t3,$t4,$t5,$t6);

my ($mask, $pwrs, $vlen) = ($s9, $s10, $s11);

my ($d0lo,$d0hi,$d1lo,$d1hi,$d2lo,$d2hi) = ($s0,$s1,$s2,$s3,$s4,$s5);
my ($r0,$r1,$r2) = ($a4,$a5,$a6);

$code.=<<___;
.type	poly1305_sqr_2_44,\@function
.align	2
poly1305_sqr_2_44:
	li	$t2, 20
	slli	$t3, $r1, 1		# r1*2
	mul	$t2, $r2, $t2		# r2*20
	slli	$t0, $r0, 1		# r0*2

	mulhu	$d2hi, $r1, $r1		# r1*r1
	mul	$d2lo, $r1, $r1
	mulhu	$t5,   $t0, $r2		# r0*2*r2
	mul	$t4,   $t0, $r2

	mulhu	$d0hi, $r0, $r0		# r0*r0
	mul	$d0lo, $r0, $r0
	mulhu	$t1,   $t3, $t2		# r1*2*r2*20
	mul	$t0,   $t3, $t2

	add	$d2lo, $d2lo, $t4
	add	$d2hi, $d2hi, $t5
	sltu	$t5,   $d2lo, $t4
	add	$d2hi, $d2hi, $t5

	mulhu	$d1hi, $r0, $t3		# r0*r1*2
	mul	$d1lo, $r0, $t3
	mulhu	$t3,   $r2, $t2		# r2*r2*20
	mul	$t2,   $r2, $t2

	add	$d0lo, $d0lo, $t0
	add	$d0hi, $d0hi, $t1
	sltu	$t1,   $d0lo, $t0
	add	$d0hi, $d0hi, $t1

	add	$d1lo, $d1lo, $t2
	add	$d1hi, $d1hi, $t3
	sltu	$t3,  $d1lo, $t2
	add	$d1hi, $d1hi, $t3

	srli	$t0, $d0lo, 44
	slli	$t1, $d0hi, 20
	and	$r0, $d0lo, $mask
	or	$t0, $t0, $t1

	srli	$t2, $d1lo, 44
	slli	$t3, $d1hi, 20
	and	$r1, $d1lo, $mask
	or	$t2, $t2, $t3
	add	$r1, $r1, $t0

	srli	$t3, $mask, 2		# 2^42-1
	srli	$t0, $d2lo, 42
	slli	$t1, $d2hi, 22
	and	$r2, $d2lo, $t3
	or	$t0, $t0, $t1
	add	$r2, $r2, $t2

	srli	$t1, $r2, 42
	and	$r2, $r2, $t3
	add	$t0, $t0, $t1

	slli	$t1, $t0, 2
	add	$r0, $r0, $t0
	add	$r0, $r0, $t1		# r0 += (d2>>42)*5

	srli	$t1, $r1, 44
	and	$r1, $r1, $mask
	add	$r2, $r2, $t1
	srli	$t0, $r0, 44
	and	$r0, $r0, $mask
	add	$r1, $r1, $t0

	ret
.size	poly1305_sqr_2_44,.-poly1305_sqr_2_44

.type	poly1305_sw_2_26,\@function
.align	2
poly1305_sw_2_26:
	srli	$t3, $mask, 18		# 2^26-1
	and	$s0, $r0, $t3
	srli	$s1, $r0, 26
	slli	$t0, $r1, 18
	and	$t0, $t0, $t3
	add	$s1, $s1, $t0
	srli	$s2, $r1, 8
	srli	$s3, $r1, 34
	slli	$t0, $r2, 10
	and	$s2, $s2, $t3
	sw	$s0, 0*28($s8)
	and	$t0, $t0, $t3
	sw	$s1, 1*28($s8)
	add	$s3, $s3, $t0
	sw	$s2, 2*28($s8)
	srli	$s4, $r2, 16
	sw	$s3, 3*28($s8)
	sw	$s4, 4*28($s8)

	ret
.size	poly1305_sw_2_26,.-poly1305_sw_2_26

.type	poly1305_lw_2_26,\@function
.align	2
poly1305_lw_2_26:
	lw	$s0, 0*28($s8)
	lw	$s1, 1*28($s8)
	lw	$s2, 2*28($s8)
	lw	$s3, 3*28($s8)
	lw	$s4, 4*28($s8)

	slli	$s1, $s1, 26
	slli	$s2, $s2, 8
	slli	$s3, $s3, 34
	add	$r0, $s0, $s1
	add	$s3, $s3, $s2
	srli	$r1, $r0, 44
	and	$r0, $r0, $mask
	add	$r1, $r1, $s3
	slli	$s4, $s4, 16
	srli	$r2, $r1, 44
	and	$r1, $r1, $mask
	add	$r2, $r2, $s4

	ret
.size	poly1305_lw_2_26,.-poly1305_lw_2_26

.globl	poly1305_blocks_vx
.type	poly1305_blocks_vx,\@function
.align	2
poly1305_blocks_vx:
	andi	$len, $len, -16		# complete blocks only
	li	$t2, 64*3
	bltu	$len, $t2, poly1305_blocks

	caddi	$sp, $sp, -16*__SIZEOF_POINTER__
	PUSH	$ra,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*8($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*7($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*6($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*5($sp)
	PUSH	$s10, __SIZEOF_POINTER__*4($sp)
	PUSH	$s11, __SIZEOF_POINTER__*3($sp)

	li	$t0, 32			# the supported upper limit
	@{[vsetvli $t0, $t0, "e32", "mf2", "ta", "ma"]}	# actual vector 1/2 size in 32-bit words
	slli	$t0, $t0, 4		# *16
	slli	$t1, $t0, 1
	add	$t2, $t1, $t0		# *3

	sltu	$t3, $len, $t2		# downsize vlen if input is too short
	srl	$t2, $t2,  $t3
	srl	$t0, $t0,  $t3
	sltu	$t3, $len, $t2
	srl	$t2, $t2,  $t3
	srl	$t0, $t0,  $t3
	sltu	$t3, $len, $t2
	srl	$t0, $t0,  $t3

	srli	$vlen, $t0, 4
	neg	$t1, $t0
	addi	$t0, $t0, -1
	and	$s4, $len, $t1		# split $len
	and	$len, $len, $t0
	cadd	$s5,  $inp, $len
	jal	poly1305_blocks
	cmove	$inp,  $s5
	mv	$len,  $s4

	lw	$s8, 48($ctx)		# top_power
	caddi	$pwrs, $ctx, 52+28

	li	$mask, -1
	srli	$mask, $mask, 20	# 2^44-1

	beqz	$s8, .Lno_pwrs

	li	$t0, -7
	sltiu	$t1, $vlen, 32
	sltiu	$t2, $vlen, 16
	 neg	$t3, $s8
	add	$t0, $t0, $t1
	sltiu	$t1, $vlen, 8
	 srli	$t3, $t3, 2
	add	$t0, $t0, $t2
	sltiu	$t2, $vlen, 4
	 addi	$t3, $t3, -1
	add	$t0, $t0, $t1
	add	$t0, $t0, $t2

	mv	$t4, $s8
	slli	$s8, $t0, 2
	bge	$s8, $t4, .Lpwrs_precomputed

	srl	$s7, $vlen, $t3
	cadd	$s8, $pwrs, $t4
	jal	poly1305_lw_2_26
	j	.Loop_pwrs_sqr		# calculate missing powers

.Lno_pwrs:
	ld	$r0, 24($ctx)		# load the key
	ld	$r1, 32($ctx)

	srli	$t0, $r0, 44		# convert the key to base 2^44
	slli	$t1, $r1, 20
	and	$r0, $r0, $mask
	srli	$r2, $r1, 24
	or	$r1, $t0, $t1
	and	$r1, $r1, $mask

	mv	$s7, $vlen
	caddi	$s8, $pwrs, -4
	jal	poly1305_sw_2_26	# key^1
.Loop_pwrs_sqr:
	srli	$s7, $s7, 1
	caddi	$s8, $s8, -4
	jal	poly1305_sqr_2_44
	jal	poly1305_sw_2_26	# key^2, key^4, key^8, ...
	bnez	$s7, .Loop_pwrs_sqr

	sub	$s8, $s8, $pwrs
	sw	$s8, 48($ctx)

.Lpwrs_precomputed:
	ld	$r0, 0($ctx)		# load the hash value
	ld	$r1, 8($ctx)
	ld	$r2, 16($ctx)

	cadd	$pwrs, $pwrs, $s8
	srli	$mask, $mask, 18	# 2^26-1

	andi	$t2, $r2, -4
	srli	$t3, $r2, 2
	and	$r2, $r2, 3
	add	$t2, $t2, $t3

	and	$s0, $r0, $mask		# convert the hash value to base 2^26
	srli	$s1, $r0, 26
	and	$s1, $s1, $mask
	srli	$s2, $r0, 52
	slli	$t0, $r1, 12
	or	$s2, $s2, $t0
	and	$s2, $s2, $mask
	srli	$s3, $r1, 14
	and	$s3, $s3, $mask
	srl	$s4, $r1, 40
	sll	$t1, $r2, 24
	or	$s4, $s4, $t1

	and	$t0, $t2, $mask
	srli	$t2, $t2, 26
	add	$s0, $s0, $t0
	and	$t1, $t2, $mask
	srli	$t2, $t2, 26
	add	$s1, $s1, $t1
	add	$s2, $s2, $t2

	slli	$padbit, $padbit, 24	# $padbit is always 1 here

	@{[vsetvli $zero, $vlen, "e32", "mf2", "ta", "ma"]}

	@{[vxor_vv $H0, $H0, $H0]}
	@{[vxor_vv $H1, $H1, $H1]}
	@{[vxor_vv $H2, $H2, $H2]}
	@{[vxor_vv $H3, $H3, $H3]}
	@{[vxor_vv $H4, $H4, $H4]}

	@{[vmv_s_x $H0, $s0]}
	@{[vmv_s_x $H1, $s1]}
	@{[vmv_s_x $H2, $s2]}
	@{[vmv_s_x $H3, $s3]}
	@{[vmv_s_x $H4, $s4]}

	slli		$t0, $vlen, 5		# chunk size
	ld		$r8_0, 0*28($pwrs)	# load two top-most powers
	ld		$r8_1, 1*28($pwrs)
	neg		$t1, $t0
	ld		$r8_2, 2*28($pwrs)
	ld		$r8_3, 3*28($pwrs)
	ld		$r8_4, 4*28($pwrs)
	caddi		$pwrs, $pwrs, 4
	cadd		$sp, $sp, $t1		# allocate alignment buffer
	andi		$t1, $inp, 3
	slli		$r8_1x5, $r8_1, 2
	slli		$r8_2x5, $r8_2, 2
	slli		$r8_3x5, $r8_3, 2
	slli		$r8_4x5, $r8_4, 2
	add		$r8_1x5, $r8_1x5, $r8_1
	add		$r8_2x5, $r8_2x5, $r8_2
	add		$r8_3x5, $r8_3x5, $r8_3
	add		$r8_4x5, $r8_4x5, $r8_4
	srli		$r4_0,   $r8_0, 32
	srli		$r4_1,   $r8_1, 32
	srli		$r4_2,   $r8_2, 32
	srli		$r4_3,   $r8_3, 32
	srli		$r4_4,   $r8_4, 32
	srli		$r4_1x5, $r8_1x5, 32
	srli		$r4_2x5, $r8_2x5, 32
	srli		$r4_3x5, $r8_3x5, 32
	srli		$r4_4x5, $r8_4x5, 32

	beqz		$t1, .Laligned_vx

	@{[vsetvli $zero, $t0, "e8", "m4", "ta", "ma"]}	# unfortunate :-(
	@{[vle8_v $INlo_0, $inp]}
	cadd		$inp, $inp, $t0
	slli		$t1, $vlen, 4
	@{[vse8_v $INlo_0, $sp]}

	@{[vsetvli $zero, $vlen, "e32", "mf2", "ta", "ma"]}
	cadd		$t1, $sp, $t1
	@{[vlseg4e32_v $INlo_0, $sp]}
	@{[vlseg4e32_v $INhi_0, $t1]}
	j		.Loop_vx_jump_in

.Loop_unaligned_vx:
	sltu		$t1, $len, $t0
	srl		$t1, $t0, $t1
	@{[vsetvli $zero, $t1, "e8", "m4", "ta", "ma"]}
	@{[vle8_v $INlo_0, $inp]}
	cadd		$inp, $inp, $t1
	slli		$t1, $vlen, 4
	@{[vse8_v $INlo_0, $sp]}

	@{[vsetvli $zero, $vlen, "e32", "mf2", "ta", "ma"]}
	cadd		$t1, $sp, $t1
	@{[vlseg4e32_v $INlo_0, $sp]}
	jal		poly1305_lazy_redc_vx
	bltu		$len, $t0, .Lodd_vx
	@{[vlseg4e32_v $INhi_0, $t1]}
	bgtu		$len, $t0, .Loop_vx_jump_in
	cmove		$inp, $t1
	j		.Loop_vx_done

.Laligned_vx:
	slli		$t1, $vlen, 4
	@{[vlseg4e32_v $INlo_0, $inp]}
	caddi		$inp, $inp, $t1
.Loop_vx:
	@{[vlseg4e32_v $INhi_0, $inp]}
	caddi		$inp, $inp, $t1

.Loop_vx_jump_in:
	sub		$len, $len, $t0
	@{[vsrl_vi $INlo_4, $INlo_3, 8]}	# base 2^32 -> 2^26
	@{[vsll_vi $INlo_3, $INlo_3, 18]}
	@{[vsrl_vi $T2, $INlo_2, 14]}
	@{[vsll_vi $INlo_2, $INlo_2, 12]}
	@{[vsrl_vi $T1, $INlo_1, 20]}
	@{[vsll_vi $INlo_1, $INlo_1, 6]}
	@{[vsrl_vi $T0, $INlo_0, 26]}
	@{[vand_vx $INlo_0, $INlo_0, $mask]}
	@{[vor_vv $INlo_3, $INlo_3, $T2]}
	@{[vor_vv $INlo_2, $INlo_2, $T1]}
	@{[vor_vv $INlo_1, $INlo_1, $T0]}
	@{[vor_vx $INlo_4, $INlo_4, $padbit]}
	@{[vand_vx $INlo_3, $INlo_3, $mask]}
	@{[vand_vx $INlo_2, $INlo_2, $mask]}
	@{[vand_vx $INlo_1, $INlo_1, $mask]}

	@{[vsrl_vi $INhi_4, $INhi_3, 8]}
	@{[vsll_vi $INhi_3, $INhi_3, 18]}
	@{[vsrl_vi $T2, $INhi_2, 14]}
	@{[vsll_vi $INhi_2, $INhi_2, 12]}
	@{[vsrl_vi $T1, $INhi_1, 20]}
	@{[vsll_vi $INhi_1, $INhi_1, 6]}
	@{[vsrl_vi $T0, $INhi_0, 26]}
	@{[vand_vx $INhi_0, $INhi_0, $mask]}
	@{[vor_vv $INhi_3, $INhi_3, $T2]}
	@{[vor_vv $INhi_2, $INhi_2, $T1]}
	@{[vor_vv $INhi_1, $INhi_1, $T0]}
	@{[vor_vx $INhi_4, $INhi_4, $padbit]}
	@{[vand_vx $INhi_3, $INhi_3, $mask]}
	@{[vand_vx $INhi_2, $INhi_2, $mask]}
	@{[vand_vx $INhi_1, $INhi_1, $mask]}

	################################################################
	# (((inp[0]*r^8 + inp[4]*r^4 + inp[8]) *r^4 + inp[12])*r^2 + )*r^2
	# (((inp[1]*r^8 + inp[5]*r^4 + inp[9]) *r^4 + inp[13])*r^2 + )*r^1
	# (((inp[2]*r^8 + inp[6]*r^4 + inp[10])*r^4 + inp[14]) ----^
	# (((inp[3]*r^8 + inp[7]*r^4 + inp[11])*r^4 + inp[15]) ----^
	#    \_____________________/
	# (((inp[0]*r^8 + inp[4]*r^4 + inp[8]) *r^8 + inp[12]*r^4 + inp[16])*r^2 + )*r^2
	# (((inp[1]*r^8 + inp[5]*r^4 + inp[9]) *r^8 + inp[13]*r^4 + inp[17])*r^2 + )*r
	# (((inp[2]*r^8 + inp[6]*r^4 + inp[10])*r^8 + inp[14]*r^4 + inp[18]) ----^
	# (((inp[3]*r^8 + inp[7]*r^4 + inp[11])*r^8 + inp[15]*r^4 + inp[19]) ----^
	#    \_____________________/ \__________________________/
	#
	# Note that we start with inp[vlen:2*vlen]*r^4. This is because
	# it doesn't depend on reduction in previous iteration, which
	# favours out-of-order execution...
	################################################################
	# d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0
	# d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*5*r4
	# d2 = h0*r2 + h1*r1   + h2*r0   + h3*5*r4 + h4*5*r3
	# d1 = h0*r1 + h1*r0   + h2*5*r4 + h3*5*r3 + h4*5*r2
	# d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1

	@{[vwmulu_vx $ACC4, $INhi_0, $r4_4]}
	@{[vwmulu_vx $ACC3, $INhi_0, $r4_3]}
	@{[vwmulu_vx $ACC2, $INhi_0, $r4_2]}
	@{[vwmulu_vx $ACC1, $INhi_0, $r4_1]}
	@{[vwmulu_vx $ACC0, $INhi_0, $r4_0]}

	@{[vwmaccu_vx $ACC4, $r4_3, $INhi_1]}
	@{[vwmaccu_vx $ACC3, $r4_2, $INhi_1]}
	@{[vwmaccu_vx $ACC2, $r4_1, $INhi_1]}
	@{[vwmaccu_vx $ACC1, $r4_0, $INhi_1]}
	@{[vwmaccu_vx $ACC0, $r4_4x5, $INhi_1]}

	@{[vwmaccu_vx $ACC4, $r4_2, $INhi_2]}
	@{[vwmaccu_vx $ACC3, $r4_1, $INhi_2]}
	@{[vwmaccu_vx $ACC2, $r4_0, $INhi_2]}
	@{[vwmaccu_vx $ACC1, $r4_4x5, $INhi_2]}
	@{[vwmaccu_vx $ACC0, $r4_3x5, $INhi_2]}

	@{[vwmaccu_vx $ACC4, $r4_1, $INhi_3]}
	@{[vwmaccu_vx $ACC3, $r4_0, $INhi_3]}
	@{[vwmaccu_vx $ACC2, $r4_4x5, $INhi_3]}
	@{[vwmaccu_vx $ACC1, $r4_3x5, $INhi_3]}
	@{[vwmaccu_vx $ACC0, $r4_2x5, $INhi_3]}

	@{[vwmaccu_vx $ACC4, $r4_0, $INhi_4]}
	@{[vwmaccu_vx $ACC3, $r4_4x5, $INhi_4]}
	@{[vwmaccu_vx $ACC2, $r4_3x5, $INhi_4]}
	@{[vwmaccu_vx $ACC1, $r4_2x5, $INhi_4]}
	@{[vwmaccu_vx $ACC0, $r4_1x5, $INhi_4]}

	################################################################
	# (hash+inp[0:vlen])^r8 and accumulate

	@{[vadd_vv $INlo_0, $INlo_0, $H0]}
	@{[vadd_vv $INlo_1, $INlo_1, $H1]}
	@{[vadd_vv $INlo_2, $INlo_2, $H2]}
	@{[vadd_vv $INlo_3, $INlo_3, $H3]}
	@{[vadd_vv $INlo_4, $INlo_4, $H4]}

	@{[vwmaccu_vx $ACC4, $r8_4, $INlo_0]}
	@{[vwmaccu_vx $ACC3, $r8_3, $INlo_0]}
	@{[vwmaccu_vx $ACC2, $r8_2, $INlo_0]}
	@{[vwmaccu_vx $ACC1, $r8_1, $INlo_0]}
	@{[vwmaccu_vx $ACC0, $r8_0, $INlo_0]}

	@{[vwmaccu_vx $ACC4, $r8_3, $INlo_1]}
	@{[vwmaccu_vx $ACC3, $r8_2, $INlo_1]}
	@{[vwmaccu_vx $ACC2, $r8_1, $INlo_1]}
	@{[vwmaccu_vx $ACC1, $r8_0, $INlo_1]}
	@{[vwmaccu_vx $ACC0, $r8_4x5, $INlo_1]}

	@{[vwmaccu_vx $ACC4, $r8_2, $INlo_2]}
	@{[vwmaccu_vx $ACC3, $r8_1, $INlo_2]}
	@{[vwmaccu_vx $ACC2, $r8_0, $INlo_2]}
	@{[vwmaccu_vx $ACC1, $r8_4x5, $INlo_2]}
	@{[vwmaccu_vx $ACC0, $r8_3x5, $INlo_2]}

	@{[vwmaccu_vx $ACC4, $r8_1, $INlo_3]}
	@{[vwmaccu_vx $ACC3, $r8_0, $INlo_3]}
	@{[vwmaccu_vx $ACC2, $r8_4x5, $INlo_3]}
	@{[vwmaccu_vx $ACC1, $r8_3x5, $INlo_3]}
	@{[vwmaccu_vx $ACC0, $r8_2x5, $INlo_3]}

	@{[vwmaccu_vx $ACC4, $r8_0, $INlo_4]}
	@{[vwmaccu_vx $ACC3, $r8_4x5, $INlo_4]}
	@{[vwmaccu_vx $ACC2, $r8_3x5, $INlo_4]}
	@{[vwmaccu_vx $ACC1, $r8_2x5, $INlo_4]}
	@{[vwmaccu_vx $ACC0, $r8_1x5, $INlo_4]}

	andi		$t1, $inp, 3
	bnez		$t1, .Loop_unaligned_vx

	slli		$t1, $vlen, 4
	@{[vlseg4e32_v $INlo_0, $inp]}
	cadd		$inp, $inp, $t1

	jal		poly1305_lazy_redc_vx

	bgtu		$len, $t0, .Loop_vx
	bltu		$len, $t0, .Lodd_vx

.Loop_vx_done:
	@{[vsrl_vi $T0, $INlo_0, 26]}	# base 2^32 -> 2^26
	@{[vand_vx $INlo_0, $INlo_0, $mask]}
	@{[vsrl_vi $T1, $INlo_1, 20]}
	@{[vsll_vi $INlo_1, $INlo_1, 6]}
	@{[vsrl_vi $T2, $INlo_2, 14]}
	@{[vsll_vi $INlo_2, $INlo_2, 12]}
	@{[vsrl_vi $INlo_4, $INlo_3, 8]}
	@{[vsll_vi $INlo_3, $INlo_3, 18]}
	@{[vor_vv $INlo_1, $INlo_1, $T0]}
	@{[vor_vv $INlo_2, $INlo_2, $T1]}
	@{[vor_vv $INlo_3, $INlo_3, $T2]}
	@{[vor_vx $INlo_4, $INlo_4, $padbit]}
	@{[vand_vx $INlo_1, $INlo_1, $mask]}
	@{[vand_vx $INlo_2, $INlo_2, $mask]}
	@{[vand_vx $INlo_3, $INlo_3, $mask]}

	@{[vadd_vv $INlo_0, $INlo_0, $H0]}
	@{[vadd_vv $INlo_1, $INlo_1, $H1]}
	@{[vadd_vv $INlo_2, $INlo_2, $H2]}
	@{[vadd_vv $INlo_3, $INlo_3, $H3]}
	@{[vadd_vv $INlo_4, $INlo_4, $H4]}

	@{[vwmulu_vx $ACC4, $INlo_0, $r4_4]}
	@{[vwmulu_vx $ACC3, $INlo_0, $r4_3]}
	@{[vwmulu_vx $ACC2, $INlo_0, $r4_2]}
	@{[vwmulu_vx $ACC1, $INlo_0, $r4_1]}
	@{[vwmulu_vx $ACC0, $INlo_0, $r4_0]}

	@{[vwmaccu_vx $ACC4, $r4_3, $INlo_1]}
	@{[vwmaccu_vx $ACC3, $r4_2, $INlo_1]}
	@{[vwmaccu_vx $ACC2, $r4_1, $INlo_1]}
	@{[vwmaccu_vx $ACC1, $r4_0, $INlo_1]}
	@{[vwmaccu_vx $ACC0, $r4_4x5, $INlo_1]}

	@{[vwmaccu_vx $ACC4, $r4_2, $INlo_2]}
	@{[vwmaccu_vx $ACC3, $r4_1, $INlo_2]}
	@{[vwmaccu_vx $ACC2, $r4_0, $INlo_2]}
	@{[vwmaccu_vx $ACC1, $r4_4x5, $INlo_2]}
	@{[vwmaccu_vx $ACC0, $r4_3x5, $INlo_2]}

	@{[vwmaccu_vx $ACC4, $r4_1, $INlo_3]}
	@{[vwmaccu_vx $ACC3, $r4_0, $INlo_3]}
	@{[vwmaccu_vx $ACC2, $r4_4x5, $INlo_3]}
	@{[vwmaccu_vx $ACC1, $r4_3x5, $INlo_3]}
	@{[vwmaccu_vx $ACC0, $r4_2x5, $INlo_3]}

	@{[vwmaccu_vx $ACC4, $r4_0, $INlo_4]}
	@{[vwmaccu_vx $ACC3, $r4_4x5, $INlo_4]}
	@{[vwmaccu_vx $ACC2, $r4_3x5, $INlo_4]}
	@{[vwmaccu_vx $ACC1, $r4_2x5, $INlo_4]}
	@{[vwmaccu_vx $ACC0, $r4_1x5, $INlo_4]}

	@{[vlseg4e32_v $INlo_0, $inp]}

	jal		poly1305_lazy_redc_vx

.Lodd_vx:
	@{[vsrl_vi $T0, $INlo_0, 26]}	# base 2^32 -> 2^26
	@{[vand_vx $INlo_0, $INlo_0, $mask]}
	@{[vsrl_vi $T1, $INlo_1, 20]}
	@{[vsll_vi $INlo_1, $INlo_1, 6]}
	@{[vsrl_vi $T2, $INlo_2, 14]}
	@{[vsll_vi $INlo_2, $INlo_2, 12]}
	@{[vsrl_vi $INlo_4, $INlo_3, 8]}
	@{[vsll_vi $INlo_3, $INlo_3, 18]}
	@{[vor_vv $INlo_1, $INlo_1, $T0]}
	@{[vor_vv $INlo_2, $INlo_2, $T1]}
	@{[vor_vv $INlo_3, $INlo_3, $T2]}
	@{[vor_vx $INlo_4, $INlo_4, $padbit]}
	@{[vand_vx $INlo_1, $INlo_1, $mask]}
	@{[vand_vx $INlo_2, $INlo_2, $mask]}
	@{[vand_vx $INlo_3, $INlo_3, $mask]}

	li		$t1, 2
	bleu		$vlen, $t1, .Last_reduce_vx

.Loop_reduce_vx:
	lw		$r4_0, 4+0*28($pwrs)	# key^2
	lw		$r4_1, 4+1*28($pwrs)
	lw		$r4_2, 4+2*28($pwrs)
	lw		$r4_3, 4+3*28($pwrs)
	lw		$r4_4, 4+4*28($pwrs)
	caddi		$pwrs, $pwrs, 4

	@{[vadd_vv $INlo_0, $INlo_0, $H0]}
	slli		$r4_1x5, $r4_1, 2
	@{[vadd_vv $INlo_1, $INlo_1, $H1]}
	slli		$r4_2x5, $r4_2, 2
	@{[vadd_vv $INlo_2, $INlo_2, $H2]}
	slli		$r4_3x5, $r4_3, 2
	@{[vadd_vv $INlo_3, $INlo_3, $H3]}
	slli		$r4_4x5, $r4_4, 2
	@{[vadd_vv $INlo_4, $INlo_4, $H4]}
	add		$r4_1x5, $r4_1x5, $r4_1

	@{[vwmulu_vx $ACC4, $INlo_0, $r4_4]}
	add		$r4_2x5, $r4_2x5, $r4_2
	@{[vwmulu_vx $ACC3, $INlo_0, $r4_3]}
	add		$r4_3x5, $r4_3x5, $r4_3
	@{[vwmulu_vx $ACC2, $INlo_0, $r4_2]}
	add		$r4_4x5, $r4_4x5, $r4_4
	@{[vwmulu_vx $ACC1, $INlo_0, $r4_1]}
	@{[vwmulu_vx $ACC0, $INlo_0, $r4_0]}

	@{[vwmaccu_vx $ACC4, $r4_3, $INlo_1]}
	@{[vwmaccu_vx $ACC3, $r4_2, $INlo_1]}
	@{[vwmaccu_vx $ACC2, $r4_1, $INlo_1]}
	@{[vwmaccu_vx $ACC1, $r4_0, $INlo_1]}
	@{[vwmaccu_vx $ACC0, $r4_4x5, $INlo_1]}

	@{[vwmaccu_vx $ACC4, $r4_2, $INlo_2]}
	@{[vwmaccu_vx $ACC3, $r4_1, $INlo_2]}
	@{[vwmaccu_vx $ACC2, $r4_0, $INlo_2]}
	@{[vwmaccu_vx $ACC1, $r4_4x5, $INlo_2]}
	@{[vwmaccu_vx $ACC0, $r4_3x5, $INlo_2]}

	@{[vwmaccu_vx $ACC4, $r4_1, $INlo_3]}
	@{[vwmaccu_vx $ACC3, $r4_0, $INlo_3]}
	@{[vwmaccu_vx $ACC2, $r4_4x5, $INlo_3]}
	@{[vwmaccu_vx $ACC1, $r4_3x5, $INlo_3]}
	@{[vwmaccu_vx $ACC0, $r4_2x5, $INlo_3]}

	@{[vwmaccu_vx $ACC4, $r4_0, $INlo_4]}
	@{[vwmaccu_vx $ACC3, $r4_4x5, $INlo_4]}
	@{[vwmaccu_vx $ACC2, $r4_3x5, $INlo_4]}
	@{[vwmaccu_vx $ACC1, $r4_2x5, $INlo_4]}
	@{[vwmaccu_vx $ACC0, $r4_1x5, $INlo_4]}

	jal		poly1305_lazy_redc_vx

	srli		$vlen, $vlen, 1
	@{[vslidedown_vx $INlo_0, $INlo_0, $vlen]}
	@{[vslidedown_vx $INlo_1, $INlo_1, $vlen]}
	@{[vslidedown_vx $INlo_2, $INlo_2, $vlen]}
	@{[vslidedown_vx $INlo_3, $INlo_3, $vlen]}
	@{[vslidedown_vx $INlo_4, $INlo_4, $vlen]}
	@{[vsetvli $zero, $vlen, "e32", "mf2", "ta", "ma"]}

	bgtu		$vlen, $t1, .Loop_reduce_vx

.Last_reduce_vx:
	caddi		$t1, $pwrs, 1*28
	@{[vle32_v $R21_0, $pwrs]}		# key^2 and key^1
	caddi		$t2, $pwrs, 2*28
	@{[vle32_v $R21_1, $t1]}
	caddi		$t3, $pwrs, 3*28
	@{[vle32_v $R21_2, $t2]}
	caddi		$t4, $pwrs, 4*28
	@{[vle32_v $R21_3, $t3]}
	@{[vle32_v $R21_4, $t4]}
	@{[vsll_vi $R21_1x5, $R21_1, 2]}
	@{[vsll_vi $R21_2x5, $R21_2, 2]}
	@{[vsll_vi $R21_3x5, $R21_3, 2]}
	@{[vsll_vi $R21_4x5, $R21_4, 2]}

	@{[vadd_vv $H0, $H0, $INlo_0]}
	@{[vadd_vv $H1, $H1, $INlo_1]}
	@{[vadd_vv $H2, $H2, $INlo_2]}
	@{[vadd_vv $H3, $H3, $INlo_3]}
	@{[vadd_vv $H4, $H4, $INlo_4]}

	@{[vadd_vv $R21_1x5, $R21_1x5, $R21_1]}
	@{[vadd_vv $R21_2x5, $R21_2x5, $R21_2]}
	@{[vadd_vv $R21_3x5, $R21_3x5, $R21_3]}
	@{[vadd_vv $R21_4x5, $R21_4x5, $R21_4]}

	@{[vwmulu_vv $ACC4, $H0, $R21_4]}
	@{[vwmulu_vv $ACC3, $H0, $R21_3]}
	@{[vwmulu_vv $ACC2, $H0, $R21_2]}
	@{[vwmulu_vv $ACC1, $H0, $R21_1]}
	@{[vwmulu_vv $ACC0, $H0, $R21_0]}

	@{[vwmaccu_vv $ACC4, $H1, $R21_3]}
	@{[vwmaccu_vv $ACC3, $H1, $R21_2]}
	@{[vwmaccu_vv $ACC2, $H1, $R21_1]}
	@{[vwmaccu_vv $ACC1, $H1, $R21_0]}
	@{[vwmaccu_vv $ACC0, $H1, $R21_4x5]}

	@{[vwmaccu_vv $ACC4, $H2, $R21_2]}
	@{[vwmaccu_vv $ACC3, $H2, $R21_1]}
	@{[vwmaccu_vv $ACC2, $H2, $R21_0]}
	@{[vwmaccu_vv $ACC1, $H2, $R21_4x5]}
	@{[vwmaccu_vv $ACC0, $H2, $R21_3x5]}

	@{[vwmaccu_vv $ACC4, $H3, $R21_1]}
	@{[vwmaccu_vv $ACC3, $H3, $R21_0]}
	@{[vwmaccu_vv $ACC2, $H3, $R21_4x5]}
	@{[vwmaccu_vv $ACC1, $H3, $R21_3x5]}
	@{[vwmaccu_vv $ACC0, $H3, $R21_2x5]}

	@{[vwmaccu_vv $ACC4, $H4, $R21_0]}
	@{[vwmaccu_vv $ACC3, $H4, $R21_4x5]}
	@{[vwmaccu_vv $ACC2, $H4, $R21_3x5]}
	@{[vwmaccu_vv $ACC1, $H4, $R21_2x5]}
	@{[vwmaccu_vv $ACC0, $H4, $R21_1x5]}

	jal		poly1305_lazy_redc_vx

	@{[vslidedown_vi $ACC0, $H0, 1]}
	@{[vslidedown_vi $ACC1, $H1, 1]}
	@{[vslidedown_vi $ACC2, $H2, 1]}
	@{[vslidedown_vi $ACC3, $H3, 1]}
	@{[vslidedown_vi $ACC4, $H4, 1]}

	@{[vadd_vv $H0, $H0, $ACC0]}
	@{[vadd_vv $H1, $H1, $ACC1]}
	@{[vadd_vv $H2, $H2, $ACC2]}
	@{[vadd_vv $H3, $H3, $ACC3]}
	@{[vadd_vv $H4, $H4, $ACC4]}

	@{[vmv_x_s $s0, $H0]}	# extract the hash value
	@{[vmv_x_s $s1, $H1]}
	@{[vmv_x_s $s2, $H2]}
	@{[vmv_x_s $s3, $H3]}
	@{[vmv_x_s $s4, $H4]}

	cadd	$sp, $sp, $t0		# drop the alignment buffer

	slli	$s1, $s1, 26		# convert the hash value to base 2^64
	slli	$t0, $s2, 52
	srli	$t1, $s2, 12
	add	$r0, $s0, $s1
	add	$r0, $r0, $t0
	sltu	$t0, $r0, $t0
	add	$r1, $t1, $t0
	slli	$s3, $s3, 14
	add	$r1, $r1, $s3
	slli	$t0, $s4, 40
	srli	$t1, $s4, 24
	add	$r1, $r1, $t0
	sltu	$t0, $r1, $t0
	add	$r2, $t1, $t0

	sd	$r0, 0($ctx)		# store the hash value
	sd	$r1, 8($ctx)
	sd	$r2, 16($ctx)

	POP	$ra,  __SIZEOF_POINTER__*15($sp)
	POP	$s0,  __SIZEOF_POINTER__*14($sp)
	POP	$s1,  __SIZEOF_POINTER__*13($sp)
	POP	$s2,  __SIZEOF_POINTER__*12($sp)
	POP	$s3,  __SIZEOF_POINTER__*11($sp)
	POP	$s4,  __SIZEOF_POINTER__*10($sp)
	POP	$s5,  __SIZEOF_POINTER__*9($sp)
	POP	$s6,  __SIZEOF_POINTER__*8($sp)
	POP	$s7,  __SIZEOF_POINTER__*7($sp)
	POP	$s8,  __SIZEOF_POINTER__*6($sp)
	POP	$s9,  __SIZEOF_POINTER__*5($sp)
	POP	$s10, __SIZEOF_POINTER__*4($sp)
	POP	$s11, __SIZEOF_POINTER__*3($sp)
	caddi	$sp, $sp, __SIZEOF_POINTER__*16
	ret
.size	poly1305_blocks_vx,.-poly1305_blocks_vx

.type	poly1305_lazy_redc_vx,\@function
.align	2
poly1305_lazy_redc_vx:
	################################################################
	# lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
	# and P. Schwabe
	#
	# H0>>+H1>>+H2>>+H3>>+H4
	# H3>>+H4>>*5+H0>>+H1
	#
	# >>+ denotes Hnext += Hn>>26, Hn &= 0x3ffffff.
	#
	# [see discussion in poly1305-armv4 module]

	@{[vsetvli $zero, $vlen, "e64", "m1", "ta", "ma"]}

	@{[vand_vx $H3, $ACC3, $mask]}
	@{[vsrl_vi $ACC3, $ACC3, 26]}
	 @{[vand_vx $H0, $ACC0, $mask]}
	 @{[vsrl_vi $ACC0, $ACC0, 26]}
	@{[vadd_vv $ACC4, $ACC4, $ACC3]}
	 @{[vadd_vv $ACC1, $ACC1, $ACC0]}

	@{[vand_vx $H4, $ACC4, $mask]}
	@{[vsrl_vi $ACC4, $ACC4, 26]}
	@{[vsll_vi $ACC0, $ACC4, 2]}
	@{[vadd_vv $H0, $H0, $ACC4]}
	 @{[vand_vx $H1, $ACC1, $mask]}
	 @{[vsrl_vi $ACC1, $ACC1, 26]}
	@{[vadd_vv $H0, $H0, $ACC0]}
	 @{[vadd_vv $ACC2, $ACC2, $ACC1]}

	@{[vsrl_vi $ACC0, $H0, 26]}
	@{[vand_vx $H0, $H0, $mask]}
	 @{[vand_vx $H2, $ACC2, $mask]}
	 @{[vsrl_vi $ACC2, $ACC2, 26]}
	@{[vadd_vv $H1, $H1, $ACC0]}
	 @{[vadd_vv $H3, $H3, $ACC2]}

	@{[vsetvli $zero, $vlen, "e32", "mf2", "ta", "ma"]}

	@{[vnsrl_wi $H0, $H0, 0]}
	@{[vnsrl_wi $H1, $H1, 0]}
	@{[vnsrl_wi $H3, $H3, 0]}
	@{[vnsrl_wi $H4, $H4, 0]}
	@{[vnsrl_wi $H2, $H2, 0]}

	@{[vsrl_vi $ACC3, $H3, 26]}
	@{[vand_vx $H3, $H3, $mask]}
	@{[vadd_vv $H4, $H4, $ACC3]}

	ret
.size	poly1305_lazy_redc_vx,.-poly1305_lazy_redc_vx
___
} # end if ($use_v) for vector code
}}}


foreach (split("\n", $code)) {
    if ($flavour =~ /^cheri/) {
	s/\(x([0-9]+)\)/(c$1)/ and s/\b([ls][bhwd]u?)\b/c$1/;
	s/\b(PUSH|POP)(\s+)x([0-9]+)/$1$2c$3/ or
	s/\b(ret|jal)\b/c$1/;
	s/\bcaddi?\b/cincoffset/ and s/\bx([0-9]+,)/c$1/g or
	m/\bcmove\b/ and s/\bx([0-9]+)/c$1/g;
    } else {
	s/\bcaddi?\b/add/ or
	s/\bcmove\b/mv/;
    }
    if (m/\bvseti*vli/) {
        s/(\be[1-8]+\b(?!,))/$1, m1, ta, mu/ or
        s/(\bmf*[1-8]\b(?!,))/$1, ta, mu/;
    }
    print $_, "\n";
}

close STDOUT;
