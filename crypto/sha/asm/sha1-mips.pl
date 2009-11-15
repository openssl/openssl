#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# SHA1 block procedure for MIPS.

# Performance improvement is 30% on unaligned input. The "secret" is
# to deploy lwl/lwr pair to load unaligned input. One could have
# vectorized Xupdate on MIPSIII/IV, but the goal was to code MIPS32-
# compatible subroutine. There is room for minor optimization on
# little-endian platforms...
#
# The code is somewhat IRIX-centric, i.e. is likely to require minor
# adaptations for other OSes...

for (@ARGV) {   $big_endian=1 if (/\-DB_ENDIAN/);
                $big_endian=0 if (/\-DL_ENDIAN/);   }
if (!defined($big_endian))
            {   $big_endian=(unpack('L',pack('N',1))==1);   }

# offsets of the Most and Least Significant Bytes
$MSB=$big_endian?0:3;
$LSB=3&~$MSB;

@X=(	"\$8",	"\$9",	"\$10",	"\$11",	"\$12",	"\$13",	"\$14",	"\$15",
	"\$16",	"\$17",	"\$18",	"\$19",	"\$20",	"\$21",	"\$22",	"\$23");
$ctx="\$4";	# a0
$inp="\$5";	# a1
$num="\$6";	# a2
$A="\$1";
$B="\$2";
$C="\$3";
$D="\$7";
$E="\$24";	@V=($A,$B,$C,$D,$E);
$t0="\$25";	# jp,t9
$t1="\$28";	# gp
$t2="\$30";	# fp,s8
$K="\$31";	# ra

$FRAMESIZE=16;

sub BODY_00_14 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
$code.=<<___	if (!$big_endian);
	srl	$t0,@X[$i],24	# byte swap($i)
	srl	$t1,@X[$i],8
	andi	$t2,@X[$i],0xFF00
	sll	@X[$i],@X[$i],24
	andi	$t1,0xFF00
	sll	$t2,$t2,8
	or	@X[$i],$t0
	or	@X[$i],$t1
	or	@X[$i],$t2
___
$code.=<<___;
	 lwl	@X[$j],$j*4+$MSB($inp)
	sll	$t0,$a,5	# $i
	addu	$e,$K
	 lwr	@X[$j],$j*4+$LSB($inp)
	srl	$t1,$a,27
	addu	$e,$t0
	xor	$t0,$c,$d
	addu	$e,$t1
	sll	$t2,$b,30
	and	$t0,$b
	srl	$b,$b,2
	xor	$t0,$d
	addu	$e,@X[$i]
	or	$b,$t2
	addu	$e,$t0
___
}

sub BODY_15_19 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;

$code.=<<___	if (!$big_endian && $i==15);
	srl	$t0,@X[$i],24	# byte swap($i)
	srl	$t1,@X[$i],8
	andi	$t2,@X[$i],0xFF00
	sll	@X[$i],@X[$i],24
	andi	$t1,0xFF00
	sll	$t2,$t2,8
	or	@X[$i],$t0
	or	@X[$i],$t1
	or	@X[$i],$t2
___
$code.=<<___;
	 xor	@X[$j%16],@X[($j+2)%16]
	sll	$t0,$a,5	# $i
	addu	$e,$K
	srl	$t1,$a,27
	addu	$e,$t0
	 xor	@X[$j%16],@X[($j+8)%16]
	xor	$t0,$c,$d
	addu	$e,$t1
	 xor	@X[$j%16],@X[($j+13)%16]
	sll	$t2,$b,30
	and	$t0,$b
	 srl	$t1,@X[$j%16],31
	 addu	@X[$j%16],@X[$j%16]
	srl	$b,$b,2
	xor	$t0,$d
	 or	@X[$j%16],$t1
	addu	$e,@X[$i%16]
	or	$b,$t2
	addu	$e,$t0
___
}

sub BODY_20_39 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
$code.=<<___ if ($i<79);
	 xor	@X[$j%16],@X[($j+2)%16]
	sll	$t0,$a,5	# $i
	addu	$e,$K
	srl	$t1,$a,27
	addu	$e,$t0
	 xor	@X[$j%16],@X[($j+8)%16]
	xor	$t0,$c,$d
	addu	$e,$t1
	 xor	@X[$j%16],@X[($j+13)%16]
	sll	$t2,$b,30
	xor	$t0,$b
	 srl	$t1,@X[$j%16],31
	 addu	@X[$j%16],@X[$j%16]
	srl	$b,$b,2
	addu	$e,@X[$i%16]
	 or	@X[$j%16],$t1
	or	$b,$t2
	addu	$e,$t0
___
$code.=<<___ if ($i==79);
	 lw	@X[0],0($ctx)
	sll	$t0,$a,5	# $i
	addu	$e,$K
	 lw	@X[1],4($ctx)
	srl	$t1,$a,27
	addu	$e,$t0
	 lw	@X[2],8($ctx)
	xor	$t0,$c,$d
	addu	$e,$t1
	 lw	@X[3],12($ctx)
	sll	$t2,$b,30
	xor	$t0,$b
	 lw	@X[4],16($ctx)
	srl	$b,$b,2
	addu	$e,@X[$i%16]
	or	$b,$t2
	addu	$e,$t0
___
}

sub BODY_40_59 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
$code.=<<___ if ($i<79);
	 xor	@X[$j%16],@X[($j+2)%16]
	sll	$t0,$a,5	# $i
	addu	$e,$K
	srl	$t1,$a,27
	addu	$e,$t0
	 xor	@X[$j%16],@X[($j+8)%16]
	and	$t0,$c,$d
	addu	$e,$t1
	 xor	@X[$j%16],@X[($j+13)%16]
	sll	$t2,$b,30
	addu	$e,$t0
	 srl	$t1,@X[$j%16],31
	xor	$t0,$c,$d
	 addu	@X[$j%16],@X[$j%16]
	and	$t0,$b
	srl	$b,$b,2
	 or	@X[$j%16],$t1
	addu	$e,@X[$i%16]
	or	$b,$t2
	addu	$e,$t0
___
}

$code=<<___;
#include <asm.h>
#include <regdef.h>

.text

.set	noat
.set	noreorder
.align	5
.globl	sha1_block_data_order
.ent	sha1_block_data_order
sha1_block_data_order:
	.frame	sp,$FRAMESIZE*SZREG,zero
	.mask	0xd0ff0000,-$FRAMESIZE*SZREG
	.set	noreorder
	PTR_SUB	sp,$FRAMESIZE*SZREG
	REG_S	\$31,($FRAMESIZE-1)*SZREG(sp)
	REG_S	\$30,($FRAMESIZE-2)*SZREG(sp)
	REG_S	\$28,($FRAMESIZE-3)*SZREG(sp)
	REG_S	\$23,($FRAMESIZE-4)*SZREG(sp)
	REG_S	\$22,($FRAMESIZE-5)*SZREG(sp)
	REG_S	\$21,($FRAMESIZE-6)*SZREG(sp)
	REG_S	\$20,($FRAMESIZE-7)*SZREG(sp)
	REG_S	\$19,($FRAMESIZE-8)*SZREG(sp)
	REG_S	\$18,($FRAMESIZE-9)*SZREG(sp)
	REG_S	\$17,($FRAMESIZE-10)*SZREG(sp)
	REG_S	\$16,($FRAMESIZE-11)*SZREG(sp)

	lw	$A,0($ctx)
	lw	$B,4($ctx)
	lw	$C,8($ctx)
	lw	$D,12($ctx)
	b	.Loop
	lw	$E,16($ctx)
.align	4
.Loop:
	.set	reorder
	lwl	@X[0],$MSB($inp)
	lui	$K,0x5a82
	lwr	@X[0],$LSB($inp)
	ori	$K,0x7999	# K_00_19
___
for ($i=0;$i<15;$i++)	{ &BODY_00_14($i,@V); unshift(@V,pop(@V)); }
for (;$i<20;$i++)	{ &BODY_15_19($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	lui	$K,0x6ed9
	ori	$K,0xeba1	# K_20_39
___
for (;$i<40;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	lui	$K,0x8f1b
	ori	$K,0xbcdc	# K_40_59
___
for (;$i<60;$i++)	{ &BODY_40_59($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	lui	$K,0xca62
	ori	$K,0xc1d6	# K_60_79
___
for (;$i<80;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	addu	$A,$X[0]
	addu	$B,$X[1]
	sw	$A,0($ctx)
	addu	$C,$X[2]
	addu	$D,$X[3]
	sw	$B,4($ctx)
	addu	$E,$X[4]
	PTR_SUB	$num,1
	sw	$C,8($ctx)
	sw	$D,12($ctx)
	sw	$E,16($ctx)
	.set	noreorder
	bnez	$num,.Loop
	PTR_ADD	$inp,64

	.set	noreorder
	REG_L	\$31,($FRAMESIZE-1)*SZREG(sp)
	REG_L	\$30,($FRAMESIZE-2)*SZREG(sp)
	REG_L	\$28,($FRAMESIZE-3)*SZREG(sp)
	REG_L	\$23,($FRAMESIZE-4)*SZREG(sp)
	REG_L	\$22,($FRAMESIZE-5)*SZREG(sp)
	REG_L	\$21,($FRAMESIZE-6)*SZREG(sp)
	REG_L	\$20,($FRAMESIZE-7)*SZREG(sp)
	REG_L	\$19,($FRAMESIZE-8)*SZREG(sp)
	REG_L	\$18,($FRAMESIZE-9)*SZREG(sp)
	REG_L	\$17,($FRAMESIZE-10)*SZREG(sp)
	REG_L	\$16,($FRAMESIZE-11)*SZREG(sp)
	jr	ra
	PTR_ADD	sp,$FRAMESIZE*SZREG
.end	sha1_block_data_order
___
print $code;
close STDOUT;
