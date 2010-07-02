#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# April 2010
#
# The module implements "4-bit" GCM GHASH function and underlying
# single multiplication operation in GF(2^128). "4-bit" means that it
# uses 256 bytes per-key table [+32 bytes shared table]. There is no
# experimental performance data available yet. The only approximation
# that can be made at this point is based on code size. Inner loop is
# 32 instructions long and on single-issue core should execute in <40
# cycles. Having verified that gcc 3.4 didn't unroll corresponding
# loop, this assembler loop body was found to be ~3x smaller than
# compiler-generated one...
#
# Note about "528B" variant. In ARM case it makes lesser sense to
# implement it for following reasons:
#
# - performance improvement won't be anywhere near 50%, because 128-
#   bit shift operation is neatly fused with 128-bit xor here, and
#   "538B" variant would eliminate only 4-5 instructions out of 32
#   in the inner loop (meaning that estimated improvement is ~15%);
# - ARM-based systems are often embedded ones and extra memory
#   consumption might be unappreciated (for so little improvement);
#
# Byte order [in]dependence. =========================================
#
# Caller is expected to maintain specific *dword* order in Htable,
# namely with *least* significant dword of 128-bit value at *lower*
# address. This differs completely from C code and has everything to
# do with ldm instruction and order in which dwords are "consumed" by
# algorithm. *Byte* order within these dwords in turn is whatever
# *native* byte order on current platform. See gcm128.c for working
# example...

$Xi="r0";	# argument block
$Htbl="r1";
$inp="r2";
$len="r3";
$Zll="r4";	# variables
$Zlh="r5";
$Zhl="r6";
$Zhh="r7";
$Tll="r8";
$Tlh="r9";
$Thl="r10";
$Thh="r11";
$nlo="r12";
################# r13 is stack pointer
$nhi="r14";
################# r15 is program counter

$rem_4bit=$inp;	# used in gcm_gmult_4bit
$cnt=$len;

$output=shift;
open STDOUT,">$output";

sub Zsmash() {
  my $i=12;
  my @args=@_;
  for ($Zll,$Zlh,$Zhl,$Zhh) {
    # can be reduced to single "str $_,[$Xi,$i]" on big-endian platforms
    $code.=<<___;
	mov	$Tlh,$_,lsr#8
	strb	$_,[$Xi,#$i+3]
	mov	$Thl,$_,lsr#16
	strb	$Tlh,[$Xi,#$i+2]
	mov	$Thh,$_,lsr#24
	strb	$Thl,[$Xi,#$i+1]
	strb	$Thh,[$Xi,#$i]
___
    $code.="\t".shift(@args)."\n";
    $i-=4;
  }
}

$code=<<___;
.text
.code	32

.type	rem_4bit,%object
.align	5
rem_4bit:
.short	0x0000,0x1C20,0x3840,0x2460
.short	0x7080,0x6CA0,0x48C0,0x54E0
.short	0xE100,0xFD20,0xD940,0xC560
.short	0x9180,0x8DA0,0xA9C0,0xB5E0
.size	rem_4bit,.-rem_4bit

.type	rem_4bit_get,%function
rem_4bit_get:
	sub	$rem_4bit,pc,#8
	sub	$rem_4bit,$rem_4bit,#32	@ &rem_4bit
	b	.Lrem_4bit_got
	nop
.size	rem_4bit_get,.-rem_4bit_get

.global	gcm_ghash_4bit
.type	gcm_ghash_4bit,%function
gcm_ghash_4bit:
	sub	r12,pc,#8
	add	$len,$inp,$len		@ $len to point at the end
	stmdb	sp!,{r3-r11,lr}		@ save $len/end too
	sub	r12,r12,#48		@ &rem_4bit

	ldmia	r12,{r4-r11}		@ copy rem_4bit ...
	stmdb	sp!,{r4-r11}		@ ... to stack

	ldrb	$nlo,[$inp,#15]
	ldrb	$nhi,[$Xi,#15]
.Louter:
	eor	$nlo,$nlo,$nhi
	and	$nhi,$nlo,#0xf0
	and	$nlo,$nlo,#0x0f
	mov	$cnt,#14

	add	$Zhh,$Htbl,$nlo,lsl#4
	ldmia	$Zhh,{$Zll-$Zhh}	@ load Htbl[nlo]
	ldrb	$nlo,[$inp,#14]

	add	$Thh,$Htbl,$nhi
	and	$nhi,$Zll,#0xf		@ rem
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nhi]
	mov	$nhi,$nhi,lsl#1
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[sp,$nhi]		@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	ldrb	$nhi,[$Xi,#14]
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	eor	$nlo,$nlo,$nhi
	eor	$Zhh,$Zhh,$Tll,lsl#16
	and	$nhi,$nlo,#0xf0
	and	$nlo,$nlo,#0x0f

.Loop:
	add	$Thh,$Htbl,$nlo,lsl#4
	subs	$cnt,$cnt,#1
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nlo]
	and	$nlo,$Zll,#0xf		@ rem
	add	$nlo,$nlo,$nlo
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[sp,$nlo]		@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	ldrplb	$nlo,[$inp,$cnt]

	add	$Thh,$Htbl,$nhi
	eor	$Zhh,$Zhh,$Tll,lsl#16	@ ^= rem_4bit[rem]
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nhi]
	and	$nhi,$Zll,#0xf		@ rem
	add	$nhi,$nhi,$nhi
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[sp,$nhi]		@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	ldrplb	$nhi,[$Xi,$cnt]
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	eorpl	$nlo,$nlo,$nhi
	eor	$Zhh,$Zhh,$Tll,lsl#16	@ ^= rem_4bit[rem]
	andpl	$nhi,$nlo,#0xf0
	andpl	$nlo,$nlo,#0x0f
	bpl	.Loop

	ldr	$len,[sp,#32]		@ re-load $len/end
	add	$inp,$inp,#16
	mov	$nhi,$Zll
___
	&Zsmash("cmp\t$inp,$len","ldrneb\t$nlo,[$inp,#15]");
$code.=<<___;
	bne	.Louter

	add	sp,sp,#36
	ldmia	sp!,{r4-r11,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
.size	gcm_ghash_4bit,.-gcm_ghash_4bit

.global	gcm_gmult_4bit
.type	gcm_gmult_4bit,%function
gcm_gmult_4bit:
	stmdb	sp!,{r4-r11,lr}
	ldrb	$nlo,[$Xi,#15]
	b	rem_4bit_get
.Lrem_4bit_got:
	and	$nhi,$nlo,#0xf0
	and	$nlo,$nlo,#0x0f
	mov	$cnt,#14

	add	$Zhh,$Htbl,$nlo,lsl#4
	ldmia	$Zhh,{$Zll-$Zhh}	@ load Htbl[nlo]
	ldrb	$nlo,[$Xi,#14]

	add	$Thh,$Htbl,$nhi
	and	$nhi,$Zll,#0xf		@ rem
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nhi]
	mov	$nhi,$nhi,lsl#1
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[$rem_4bit,$nhi]	@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	and	$nhi,$nlo,#0xf0
	eor	$Zhh,$Zhh,$Tll,lsl#16
	and	$nlo,$nlo,#0x0f

.Loop2:
	add	$Thh,$Htbl,$nlo,lsl#4
	subs	$cnt,$cnt,#1
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nlo]
	and	$nlo,$Zll,#0xf		@ rem
	add	$nlo,$nlo,$nlo
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[$rem_4bit,$nlo]	@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	ldrplb	$nlo,[$Xi,$cnt]

	add	$Thh,$Htbl,$nhi
	eor	$Zhh,$Zhh,$Tll,lsl#16	@ ^= rem_4bit[rem]
	ldmia	$Thh,{$Tll-$Thh}	@ load Htbl[nhi]
	and	$nhi,$Zll,#0xf		@ rem
	add	$nhi,$nhi,$nhi
	eor	$Zll,$Tll,$Zll,lsr#4
	ldrh	$Tll,[$rem_4bit,$nhi]	@ rem_4bit[rem]
	eor	$Zll,$Zll,$Zlh,lsl#28
	eor	$Zlh,$Tlh,$Zlh,lsr#4
	eor	$Zlh,$Zlh,$Zhl,lsl#28
	eor	$Zhl,$Thl,$Zhl,lsr#4
	eor	$Zhl,$Zhl,$Zhh,lsl#28
	eor	$Zhh,$Thh,$Zhh,lsr#4
	andpl	$nhi,$nlo,#0xf0
	eor	$Zhh,$Zhh,$Tll,lsl#16	@ ^= rem_4bit[rem]
	andpl	$nlo,$nlo,#0x0f
	bpl	.Loop2
___
	&Zsmash();
$code.=<<___;
	ldmia	sp!,{r4-r11,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
.size	gcm_gmult_4bit,.-gcm_gmult_4bit
.asciz  "GHASH for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
.align  2
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
$code =~ s/\bbx\s+lr\b/.word\t0xe12fff1e/gm;	# make it possible to compile with -march=armv4
print $code;
close STDOUT; # enforce flush
