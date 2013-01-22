#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# I let hardware handle unaligned input, except on page boundaries
# (see below for details). Otherwise straightforward implementation
# with X vector in register bank. The module is big-endian [which is
# not big deal as there're no little-endian targets left around].

#			sha256		|	sha512
# 			-m64	-m32	|	-m64	-m32
# --------------------------------------+-----------------------
# PPC970,gcc-4.0.0	+50%	+38%	|	+40%	+410%(*)
# Power6,xlc-7		+150%	+90%	|	+100%	+430%(*)
#
# (*)	64-bit code in 32-bit application context, which actually is
#	on TODO list. It should be noted that for safe deployment in
#	32-bit *mutli-threaded* context asyncronous signals should be
#	blocked upon entry to SHA512 block routine. This is because
#	32-bit signaling procedure invalidates upper halves of GPRs.
#	Context switch procedure preserves them, but not signaling:-(

# Second version is true multi-thread safe. Trouble with the original
# version was that it was using thread local storage pointer register.
# Well, it scrupulously preserved it, but the problem would arise the
# moment asynchronous signal was delivered and signal handler would
# dereference the TLS pointer. While it's never the case in openssl
# application or test suite, we have to respect this scenario and not
# use TLS pointer register. Alternative would be to require caller to
# block signals prior calling this routine. For the record, in 32-bit
# context R2 serves as TLS pointer, while in 64-bit context - R13.

$flavour=shift;
$output =shift;

if ($flavour =~ /64/) {
	$SIZE_T=8;
	$LRSAVE=2*$SIZE_T;
	$STU="stdu";
	$UCMP="cmpld";
	$SHL="sldi";
	$POP="ld";
	$PUSH="std";
} elsif ($flavour =~ /32/) {
	$SIZE_T=4;
	$LRSAVE=$SIZE_T;
	$STU="stwu";
	$UCMP="cmplw";
	$SHL="slwi";
	$POP="lwz";
	$PUSH="stw";
} else { die "nonsense $flavour"; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output" || die "can't call $xlate: $!";

if ($output =~ /512/) {
	$func="sha512_block_data_order";
	$SZ=8;
	@Sigma0=(28,34,39);
	@Sigma1=(14,18,41);
	@sigma0=(1,  8, 7);
	@sigma1=(19,61, 6);
	$rounds=80;
	$LD="ld";
	$ST="std";
	$ROR="rotrdi";
	$SHR="srdi";
} else {
	$func="sha256_block_data_order";
	$SZ=4;
	@Sigma0=( 2,13,22);
	@Sigma1=( 6,11,25);
	@sigma0=( 7,18, 3);
	@sigma1=(17,19,10);
	$rounds=64;
	$LD="lwz";
	$ST="stw";
	$ROR="rotrwi";
	$SHR="srwi";
}

$FRAME=32*$SIZE_T+16*$SZ;
$LOCALS=6*$SIZE_T;

$sp ="r1";
$toc="r2";
$ctx="r3";	# zapped by $a0
$inp="r4";	# zapped by $a1
$num="r5";	# zapped by $t0

$T  ="r0";
$a0 ="r3";
$a1 ="r4";
$t0 ="r5";
$t1 ="r6";
$Tbl="r7";

$A  ="r8";
$B  ="r9";
$C  ="r10";
$D  ="r11";
$E  ="r12";
$F  =$t1;	$t1 = "r0";	# stay away from "r13";
$G  ="r14";
$H  ="r15";

@V=($A,$B,$C,$D,$E,$F,$G,$H);
@X=("r16","r17","r18","r19","r20","r21","r22","r23",
    "r24","r25","r26","r27","r28","r29","r30","r31");

$inp="r31" if($SZ==4 || $SIZE_T==8);	# reassigned $inp! aliases with @X[15]

sub ROUND_00_15 {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;
$code.=<<___;
	$ROR	$a0,$e,$Sigma1[0]
	$ROR	$a1,$e,$Sigma1[1]
	and	$t0,$f,$e
	xor	$a0,$a0,$a1
	add	$h,$h,$t1
	andc	$t1,$g,$e
	$ROR	$a1,$a1,`$Sigma1[2]-$Sigma1[1]`
	or	$t0,$t0,$t1		; Ch(e,f,g)
	add	$h,$h,@X[$i%16]
	xor	$a0,$a0,$a1		; Sigma1(e)
	add	$h,$h,$t0
	add	$h,$h,$a0

	$ROR	$a0,$a,$Sigma0[0]
	$ROR	$a1,$a,$Sigma0[1]
	and	$t0,$a,$b
	and	$t1,$a,$c
	xor	$a0,$a0,$a1
	$ROR	$a1,$a1,`$Sigma0[2]-$Sigma0[1]`
	xor	$t0,$t0,$t1
	and	$t1,$b,$c
	xor	$a0,$a0,$a1		; Sigma0(a)
	add	$d,$d,$h
	xor	$t0,$t0,$t1		; Maj(a,b,c)
___
$code.=<<___ if ($i<15);
	$LD	$t1,`($i+1)*$SZ`($Tbl)
___
$code.=<<___;
	add	$h,$h,$a0
	add	$h,$h,$t0

___
}

sub ROUND_16_xx {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;
$i-=16;
$code.=<<___;
	$ROR	$a0,@X[($i+1)%16],$sigma0[0]
	$ROR	$a1,@X[($i+1)%16],$sigma0[1]
	$ROR	$t0,@X[($i+14)%16],$sigma1[0]
	$ROR	$t1,@X[($i+14)%16],$sigma1[1]
	xor	$a0,$a0,$a1
	$SHR	$a1,@X[($i+1)%16],$sigma0[2]
	xor	$t0,$t0,$t1
	$SHR	$t1,@X[($i+14)%16],$sigma1[2]
	add	@X[$i],@X[$i],@X[($i+9)%16]
	xor	$a0,$a0,$a1		; sigma0(X[(i+1)&0x0f])
	xor	$t0,$t0,$t1		; sigma1(X[(i+14)&0x0f])
	$LD	$t1,`$i*$SZ`($Tbl)
	add	@X[$i],@X[$i],$a0
	add	@X[$i],@X[$i],$t0
___
&ROUND_00_15($i+16,$a,$b,$c,$d,$e,$f,$g,$h);
}

$code=<<___;
.machine	"any"
.text

.globl	$func
.align	6
$func:
	$STU	$sp,-$FRAME($sp)
	mflr	r0
	$SHL	$num,$num,`log(16*$SZ)/log(2)`

	$PUSH	$ctx,`$FRAME-$SIZE_T*22`($sp)

	$PUSH	r14,`$FRAME-$SIZE_T*18`($sp)
	$PUSH	r15,`$FRAME-$SIZE_T*17`($sp)
	$PUSH	r16,`$FRAME-$SIZE_T*16`($sp)
	$PUSH	r17,`$FRAME-$SIZE_T*15`($sp)
	$PUSH	r18,`$FRAME-$SIZE_T*14`($sp)
	$PUSH	r19,`$FRAME-$SIZE_T*13`($sp)
	$PUSH	r20,`$FRAME-$SIZE_T*12`($sp)
	$PUSH	r21,`$FRAME-$SIZE_T*11`($sp)
	$PUSH	r22,`$FRAME-$SIZE_T*10`($sp)
	$PUSH	r23,`$FRAME-$SIZE_T*9`($sp)
	$PUSH	r24,`$FRAME-$SIZE_T*8`($sp)
	$PUSH	r25,`$FRAME-$SIZE_T*7`($sp)
	$PUSH	r26,`$FRAME-$SIZE_T*6`($sp)
	$PUSH	r27,`$FRAME-$SIZE_T*5`($sp)
	$PUSH	r28,`$FRAME-$SIZE_T*4`($sp)
	$PUSH	r29,`$FRAME-$SIZE_T*3`($sp)
	$PUSH	r30,`$FRAME-$SIZE_T*2`($sp)
	$PUSH	r31,`$FRAME-$SIZE_T*1`($sp)
	$PUSH	r0,`$FRAME+$LRSAVE`($sp)
___

if ($SZ==4 || $SIZE_T==8) {
$code.=<<___;
	$LD	$A,`0*$SZ`($ctx)
	mr	$inp,r4				; incarnate $inp
	$LD	$B,`1*$SZ`($ctx)
	$LD	$C,`2*$SZ`($ctx)
	$LD	$D,`3*$SZ`($ctx)
	$LD	$E,`4*$SZ`($ctx)
	$LD	$F,`5*$SZ`($ctx)
	$LD	$G,`6*$SZ`($ctx)
	$LD	$H,`7*$SZ`($ctx)
___
} else {
  for ($i=16;$i<32;$i++) {
    $code.=<<___;
	lwz	r$i,`4*($i-16)`($ctx)
___
  }
}

$code.=<<___;
	bl	LPICmeup
LPICedup:
	andi.	r0,$inp,3
	bne	Lunaligned
Laligned:
	add	$num,$inp,$num
	$PUSH	$num,`$FRAME-$SIZE_T*24`($sp)	; end pointer
	$PUSH	$inp,`$FRAME-$SIZE_T*23`($sp)	; inp pointer
	bl	Lsha2_block_private
	b	Ldone

; PowerPC specification allows an implementation to be ill-behaved
; upon unaligned access which crosses page boundary. "Better safe
; than sorry" principle makes me treat it specially. But I don't
; look for particular offending word, but rather for the input
; block which crosses the boundary. Once found that block is aligned
; and hashed separately...
.align	4
Lunaligned:
	subfic	$t1,$inp,4096
	andi.	$t1,$t1,`4096-16*$SZ`	; distance to closest page boundary
	beq	Lcross_page
	$UCMP	$num,$t1
	ble-	Laligned		; didn't cross the page boundary
	subfc	$num,$t1,$num
	add	$t1,$inp,$t1
	$PUSH	$num,`$FRAME-$SIZE_T*25`($sp)	; save real remaining num
	$PUSH	$t1,`$FRAME-$SIZE_T*24`($sp)	; intermediate end pointer
	$PUSH	$inp,`$FRAME-$SIZE_T*23`($sp)	; inp pointer
	bl	Lsha2_block_private
	; $inp equals to the intermediate end pointer here
	$POP	$num,`$FRAME-$SIZE_T*25`($sp)	; restore real remaining num
Lcross_page:
	li	$t1,`16*$SZ/4`
	mtctr	$t1
___
if ($SZ==4 || $SIZE_T==8) {
$code.=<<___;
	addi	r20,$sp,$LOCALS			; aligned spot below the frame
Lmemcpy:
	lbz	r16,0($inp)
	lbz	r17,1($inp)
	lbz	r18,2($inp)
	lbz	r19,3($inp)
	addi	$inp,$inp,4
	stb	r16,0(r20)
	stb	r17,1(r20)
	stb	r18,2(r20)
	stb	r19,3(r20)
	addi	r20,r20,4
	bdnz	Lmemcpy
___
} else {
$code.=<<___;
	addi	r12,$sp,$LOCALS			; aligned spot below the frame
Lmemcpy:
	lbz	r8,0($inp)
	lbz	r9,1($inp)
	lbz	r10,2($inp)
	lbz	r11,3($inp)
	addi	$inp,$inp,4
	stb	r8,0(r12)
	stb	r9,1(r12)
	stb	r10,2(r12)
	stb	r11,3(r12)
	addi	r12,r12,4
	bdnz	Lmemcpy
___
}

$code.=<<___;
	$PUSH	$inp,`$FRAME-$SIZE_T*26`($sp)	; save real inp
	addi	$t1,$sp,`$LOCALS+16*$SZ`	; fictitious end pointer
	addi	$inp,$sp,$LOCALS		; fictitious inp pointer
	$PUSH	$num,`$FRAME-$SIZE_T*25`($sp)	; save real num
	$PUSH	$t1,`$FRAME-$SIZE_T*24`($sp)	; end pointer
	$PUSH	$inp,`$FRAME-$SIZE_T*23`($sp)	; inp pointer
	bl	Lsha2_block_private
	$POP	$inp,`$FRAME-$SIZE_T*26`($sp)	; restore real inp
	$POP	$num,`$FRAME-$SIZE_T*25`($sp)	; restore real num
	addic.	$num,$num,`-16*$SZ`		; num--
	bne-	Lunaligned

Ldone:
	$POP	r0,`$FRAME+$LRSAVE`($sp)
	$POP	r14,`$FRAME-$SIZE_T*18`($sp)
	$POP	r15,`$FRAME-$SIZE_T*17`($sp)
	$POP	r16,`$FRAME-$SIZE_T*16`($sp)
	$POP	r17,`$FRAME-$SIZE_T*15`($sp)
	$POP	r18,`$FRAME-$SIZE_T*14`($sp)
	$POP	r19,`$FRAME-$SIZE_T*13`($sp)
	$POP	r20,`$FRAME-$SIZE_T*12`($sp)
	$POP	r21,`$FRAME-$SIZE_T*11`($sp)
	$POP	r22,`$FRAME-$SIZE_T*10`($sp)
	$POP	r23,`$FRAME-$SIZE_T*9`($sp)
	$POP	r24,`$FRAME-$SIZE_T*8`($sp)
	$POP	r25,`$FRAME-$SIZE_T*7`($sp)
	$POP	r26,`$FRAME-$SIZE_T*6`($sp)
	$POP	r27,`$FRAME-$SIZE_T*5`($sp)
	$POP	r28,`$FRAME-$SIZE_T*4`($sp)
	$POP	r29,`$FRAME-$SIZE_T*3`($sp)
	$POP	r30,`$FRAME-$SIZE_T*2`($sp)
	$POP	r31,`$FRAME-$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,4,1,0x80,18,3,0
	.long	0
___

if ($SZ==4 || $SIZE_T==8) {
$code.=<<___;
.align	4
Lsha2_block_private:
	$LD	$t1,0($Tbl)
___
for($i=0;$i<16;$i++) {
$code.=<<___ if ($SZ==4);
	lwz	@X[$i],`$i*$SZ`($inp)
___
# 64-bit loads are split to 2x32-bit ones, as CPU can't handle
# unaligned 64-bit loads, only 32-bit ones...
$code.=<<___ if ($SZ==8);
	lwz	$t0,`$i*$SZ`($inp)
	lwz	@X[$i],`$i*$SZ+4`($inp)
	insrdi	@X[$i],$t0,32,0
___
	&ROUND_00_15($i,@V);
	unshift(@V,pop(@V));
}
$code.=<<___;
	li	$t0,`$rounds/16-1`
	mtctr	$t0
.align	4
Lrounds:
	addi	$Tbl,$Tbl,`16*$SZ`
___
for(;$i<32;$i++) {
	&ROUND_16_xx($i,@V);
	unshift(@V,pop(@V));
}
$code.=<<___;
	bdnz-	Lrounds

	$POP	$ctx,`$FRAME-$SIZE_T*22`($sp)
	$POP	$inp,`$FRAME-$SIZE_T*23`($sp)	; inp pointer
	$POP	$num,`$FRAME-$SIZE_T*24`($sp)	; end pointer
	subi	$Tbl,$Tbl,`($rounds-16)*$SZ`	; rewind Tbl

	$LD	r16,`0*$SZ`($ctx)
	$LD	r17,`1*$SZ`($ctx)
	$LD	r18,`2*$SZ`($ctx)
	$LD	r19,`3*$SZ`($ctx)
	$LD	r20,`4*$SZ`($ctx)
	$LD	r21,`5*$SZ`($ctx)
	$LD	r22,`6*$SZ`($ctx)
	addi	$inp,$inp,`16*$SZ`		; advance inp
	$LD	r23,`7*$SZ`($ctx)
	add	$A,$A,r16
	add	$B,$B,r17
	$PUSH	$inp,`$FRAME-$SIZE_T*23`($sp)
	add	$C,$C,r18
	$ST	$A,`0*$SZ`($ctx)
	add	$D,$D,r19
	$ST	$B,`1*$SZ`($ctx)
	add	$E,$E,r20
	$ST	$C,`2*$SZ`($ctx)
	add	$F,$F,r21
	$ST	$D,`3*$SZ`($ctx)
	add	$G,$G,r22
	$ST	$E,`4*$SZ`($ctx)
	add	$H,$H,r23
	$ST	$F,`5*$SZ`($ctx)
	$ST	$G,`6*$SZ`($ctx)
	$UCMP	$inp,$num
	$ST	$H,`7*$SZ`($ctx)
	bne	Lsha2_block_private
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
___
} else {
########################################################################
# SHA512 for PPC32, X vector is off-loaded to stack...
#
#			|	sha512
#			|	-m32
# ----------------------+-----------------------
# PPC74x0,gcc-4.0.1	|	+48%
# POWER6,gcc-4.4.6	|	+124%(*)
# POWER7,gcc-4.4.6	|	+79%(*)
# e300,gcc-4.1.0	|	+167%
#
# (*)	~1/3 of -m64 result [and ~20% better than -m32 code generated
#	by xlc-12.1]

my $XOFF=$LOCALS;

my @V=map("r$_",(16..31));	# A..H

my ($s0,$s1,$t0,$t1,$t2,$t3,$a0,$a1,$a2,$a3)=map("r$_",(0,5,6,8..12,14,15));
my ($x0,$x1)=("r3","r4");	# zaps $ctx and $inp

sub ROUND_00_15_ppc32 {
my ($i,	$ahi,$alo,$bhi,$blo,$chi,$clo,$dhi,$dlo,
	$ehi,$elo,$fhi,$flo,$ghi,$glo,$hhi,$hlo)=@_;

$code.=<<___;
	lwz	$t2,`$SZ*($i%16)+4`($Tbl)
	 xor	$a0,$flo,$glo
	lwz	$t3,`$SZ*($i%16)+0`($Tbl)
	 xor	$a1,$fhi,$ghi
	addc	$hlo,$hlo,$t0			; h+=x[i]
	stw	$t0,`$XOFF+0+$SZ*($i%16)`($sp)	; save x[i]

	srwi	$s0,$elo,$Sigma1[0]
	srwi	$s1,$ehi,$Sigma1[0]
	 and	$a0,$a0,$elo
	adde	$hhi,$hhi,$t1
	 and	$a1,$a1,$ehi
	stw	$t1,`$XOFF+4+$SZ*($i%16)`($sp)
	srwi	$t0,$elo,$Sigma1[1]
	srwi	$t1,$ehi,$Sigma1[1]
	 addc	$hlo,$hlo,$t2			; h+=K512[i]
	insrwi	$s0,$ehi,$Sigma1[0],0
	insrwi	$s1,$elo,$Sigma1[0],0
	 xor	$a0,$a0,$glo			; Ch(e,f,g)
	 adde	$hhi,$hhi,$t3
	 xor	$a1,$a1,$ghi
	insrwi	$t0,$ehi,$Sigma1[1],0
	insrwi	$t1,$elo,$Sigma1[1],0
	 addc	$hlo,$hlo,$a0			; h+=Ch(e,f,g)
	srwi	$t2,$ehi,$Sigma1[2]-32
	srwi	$t3,$elo,$Sigma1[2]-32
	xor	$s0,$s0,$t0
	xor	$s1,$s1,$t1
	insrwi	$t2,$elo,$Sigma1[2]-32,0
	insrwi	$t3,$ehi,$Sigma1[2]-32,0
	 xor	$a0,$alo,$blo			; a^b, b^c in next round
	 adde	$hhi,$hhi,$a1
	 xor	$a1,$ahi,$bhi
	xor	$s0,$s0,$t2			; Sigma1(e)
	xor	$s1,$s1,$t3

	srwi	$t0,$alo,$Sigma0[0]
	 and	$a2,$a2,$a0
	 addc	$hlo,$hlo,$s0			; h+=Sigma1(e)
	 and	$a3,$a3,$a1
	srwi	$t1,$ahi,$Sigma0[0]
	srwi	$s0,$ahi,$Sigma0[1]-32
	 adde	$hhi,$hhi,$s1
	srwi	$s1,$alo,$Sigma0[1]-32
	insrwi	$t0,$ahi,$Sigma0[0],0
	insrwi	$t1,$alo,$Sigma0[0],0
	 xor	$a2,$a2,$blo			; Maj(a,b,c)
	 addc	$dlo,$dlo,$hlo			; d+=h
	 xor	$a3,$a3,$bhi
	insrwi	$s0,$alo,$Sigma0[1]-32,0
	insrwi	$s1,$ahi,$Sigma0[1]-32,0
	 adde	$dhi,$dhi,$hhi
	srwi	$t2,$ahi,$Sigma0[2]-32
	srwi	$t3,$alo,$Sigma0[2]-32
	xor	$s0,$s0,$t0
	 addc	$hlo,$hlo,$a2			; h+=Maj(a,b,c)
	xor	$s1,$s1,$t1
	insrwi	$t2,$alo,$Sigma0[2]-32,0
	insrwi	$t3,$ahi,$Sigma0[2]-32,0
	 adde	$hhi,$hhi,$a3
___
$code.=<<___ if ($i>=15);
	lwz	$t0,`$XOFF+0+$SZ*(($i+2)%16)`($sp)
	lwz	$t1,`$XOFF+4+$SZ*(($i+2)%16)`($sp)
___
$code.=<<___ if ($i<15);
	lwz	$t1,`$SZ*($i+1)+0`($inp)
	lwz	$t0,`$SZ*($i+1)+4`($inp)
___
$code.=<<___;
	xor	$s0,$s0,$t2			; Sigma0(a)
	xor	$s1,$s1,$t3
	addc	$hlo,$hlo,$s0			; h+=Sigma0(a)
	adde	$hhi,$hhi,$s1
___
$code.=<<___ if ($i==15);
	lwz	$x0,`$XOFF+0+$SZ*(($i+1)%16)`($sp)
	lwz	$x1,`$XOFF+4+$SZ*(($i+1)%16)`($sp)
___
}
sub ROUND_16_xx_ppc32 {
my ($i,	$ahi,$alo,$bhi,$blo,$chi,$clo,$dhi,$dlo,
	$ehi,$elo,$fhi,$flo,$ghi,$glo,$hhi,$hlo)=@_;

$code.=<<___;
	srwi	$s0,$t0,$sigma0[0]
	srwi	$s1,$t1,$sigma0[0]
	srwi	$t2,$t0,$sigma0[1]
	srwi	$t3,$t1,$sigma0[1]
	insrwi	$s0,$t1,$sigma0[0],0
	insrwi	$s1,$t0,$sigma0[0],0
	srwi	$a0,$t0,$sigma0[2]
	insrwi	$t2,$t1,$sigma0[1],0
	insrwi	$t3,$t0,$sigma0[1],0
	insrwi	$a0,$t1,$sigma0[2],0
	xor	$s0,$s0,$t2
	 lwz	$t2,`$XOFF+0+$SZ*(($i+14)%16)`($sp)
	srwi	$a1,$t1,$sigma0[2]
	xor	$s1,$s1,$t3
	 lwz	$t3,`$XOFF+4+$SZ*(($i+14)%16)`($sp)
	xor	$a0,$a0,$s0
	 srwi	$s0,$t2,$sigma1[0]
	xor	$a1,$a1,$s1
	 srwi	$s1,$t3,$sigma1[0]
	addc	$x0,$x0,$a0			; x[i]+=sigma0(x[i+1])
	 srwi	$a0,$t3,$sigma1[1]-32
	insrwi	$s0,$t3,$sigma1[0],0
	insrwi	$s1,$t2,$sigma1[0],0
	adde	$x1,$x1,$a1
	 srwi	$a1,$t2,$sigma1[1]-32

	insrwi	$a0,$t2,$sigma1[1]-32,0
	srwi	$t2,$t2,$sigma1[2]
	insrwi	$a1,$t3,$sigma1[1]-32,0
	insrwi	$t2,$t3,$sigma1[2],0
	xor	$s0,$s0,$a0
	 lwz	$a0,`$XOFF+0+$SZ*(($i+9)%16)`($sp)
	srwi	$t3,$t3,$sigma1[2]
	xor	$s1,$s1,$a1
	 lwz	$a1,`$XOFF+4+$SZ*(($i+9)%16)`($sp)
	xor	$s0,$s0,$t2
	 addc	$x0,$x0,$a0			; x[i]+=x[i+9]
	xor	$s1,$s1,$t3
	 adde	$x1,$x1,$a1
	addc	$x0,$x0,$s0			; x[i]+=sigma1(x[i+14])
	adde	$x1,$x1,$s1
___
	($t0,$t1,$x0,$x1) = ($x0,$x1,$t0,$t1);
	&ROUND_00_15_ppc32(@_);
}

$code.=<<___;
.align	4
Lsha2_block_private:
	lwz	$t1,0($inp)
	xor	$a2,@V[3],@V[5]		; B^C, magic seed
	lwz	$t0,4($inp)
	xor	$a3,@V[2],@V[4]
___
for($i=0;$i<16;$i++) {
	&ROUND_00_15_ppc32($i,@V);
	unshift(@V,pop(@V));	unshift(@V,pop(@V));
	($a0,$a1,$a2,$a3) = ($a2,$a3,$a0,$a1);
}
$code.=<<___;
	li	$a0,`$rounds/16-1`
	mtctr	$a0
.align	4
Lrounds:
	addi	$Tbl,$Tbl,`16*$SZ`
___
for(;$i<32;$i++) {
	&ROUND_16_xx_ppc32($i,@V);
	unshift(@V,pop(@V));	unshift(@V,pop(@V));
	($a0,$a1,$a2,$a3) = ($a2,$a3,$a0,$a1);
}
$code.=<<___;
	bdnz-	Lrounds

	$POP	$ctx,`$FRAME-$SIZE_T*22`($sp)
	$POP	$inp,`$FRAME-$SIZE_T*23`($sp)	; inp pointer
	$POP	$num,`$FRAME-$SIZE_T*24`($sp)	; end pointer
	subi	$Tbl,$Tbl,`($rounds-16)*$SZ`	; rewind Tbl

	lwz	$t0,0($ctx)
	lwz	$t1,4($ctx)
	lwz	$t2,8($ctx)
	lwz	$t3,12($ctx)
	lwz	$a0,16($ctx)
	lwz	$a1,20($ctx)
	lwz	$a2,24($ctx)
	addc	@V[1],@V[1],$t1
	lwz	$a3,28($ctx)
	adde	@V[0],@V[0],$t0
	lwz	$t0,32($ctx)
	addc	@V[3],@V[3],$t3
	lwz	$t1,36($ctx)
	adde	@V[2],@V[2],$t2
	lwz	$t2,40($ctx)
	addc	@V[5],@V[5],$a1
	lwz	$t3,44($ctx)
	adde	@V[4],@V[4],$a0
	lwz	$a0,48($ctx)
	addc	@V[7],@V[7],$a3
	lwz	$a1,52($ctx)
	adde	@V[6],@V[6],$a2
	lwz	$a2,56($ctx)
	addc	@V[9],@V[9],$t1
	lwz	$a3,60($ctx)
	adde	@V[8],@V[8],$t0
	stw	@V[0],0($ctx)
	stw	@V[1],4($ctx)
	addc	@V[11],@V[11],$t3
	stw	@V[2],8($ctx)
	stw	@V[3],12($ctx)
	adde	@V[10],@V[10],$t2
	stw	@V[4],16($ctx)
	stw	@V[5],20($ctx)
	addc	@V[13],@V[13],$a1
	stw	@V[6],24($ctx)
	stw	@V[7],28($ctx)
	adde	@V[12],@V[12],$a0
	stw	@V[8],32($ctx)
	stw	@V[9],36($ctx)
	addc	@V[15],@V[15],$a3
	stw	@V[10],40($ctx)
	stw	@V[11],44($ctx)
	adde	@V[14],@V[14],$a2
	stw	@V[12],48($ctx)
	stw	@V[13],52($ctx)
	stw	@V[14],56($ctx)
	stw	@V[15],60($ctx)

	addi	$inp,$inp,`16*$SZ`		; advance inp
	$PUSH	$inp,`$FRAME-$SIZE_T*23`($sp)
	$UCMP	$inp,$num
	bne	Lsha2_block_private
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
___
}

# Ugly hack here, because PPC assembler syntax seem to vary too
# much from platforms to platform...
$code.=<<___;
.align	6
LPICmeup:
	mflr	r0
	bcl	20,31,\$+4
	mflr	$Tbl	; vvvvvv "distance" between . and 1st data entry
	addi	$Tbl,$Tbl,`64-8`
	mtlr	r0
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
	.space	`64-9*4`
___
$code.=<<___ if ($SZ==8);
	.long	0x428a2f98,0xd728ae22,0x71374491,0x23ef65cd
	.long	0xb5c0fbcf,0xec4d3b2f,0xe9b5dba5,0x8189dbbc
	.long	0x3956c25b,0xf348b538,0x59f111f1,0xb605d019
	.long	0x923f82a4,0xaf194f9b,0xab1c5ed5,0xda6d8118
	.long	0xd807aa98,0xa3030242,0x12835b01,0x45706fbe
	.long	0x243185be,0x4ee4b28c,0x550c7dc3,0xd5ffb4e2
	.long	0x72be5d74,0xf27b896f,0x80deb1fe,0x3b1696b1
	.long	0x9bdc06a7,0x25c71235,0xc19bf174,0xcf692694
	.long	0xe49b69c1,0x9ef14ad2,0xefbe4786,0x384f25e3
	.long	0x0fc19dc6,0x8b8cd5b5,0x240ca1cc,0x77ac9c65
	.long	0x2de92c6f,0x592b0275,0x4a7484aa,0x6ea6e483
	.long	0x5cb0a9dc,0xbd41fbd4,0x76f988da,0x831153b5
	.long	0x983e5152,0xee66dfab,0xa831c66d,0x2db43210
	.long	0xb00327c8,0x98fb213f,0xbf597fc7,0xbeef0ee4
	.long	0xc6e00bf3,0x3da88fc2,0xd5a79147,0x930aa725
	.long	0x06ca6351,0xe003826f,0x14292967,0x0a0e6e70
	.long	0x27b70a85,0x46d22ffc,0x2e1b2138,0x5c26c926
	.long	0x4d2c6dfc,0x5ac42aed,0x53380d13,0x9d95b3df
	.long	0x650a7354,0x8baf63de,0x766a0abb,0x3c77b2a8
	.long	0x81c2c92e,0x47edaee6,0x92722c85,0x1482353b
	.long	0xa2bfe8a1,0x4cf10364,0xa81a664b,0xbc423001
	.long	0xc24b8b70,0xd0f89791,0xc76c51a3,0x0654be30
	.long	0xd192e819,0xd6ef5218,0xd6990624,0x5565a910
	.long	0xf40e3585,0x5771202a,0x106aa070,0x32bbd1b8
	.long	0x19a4c116,0xb8d2d0c8,0x1e376c08,0x5141ab53
	.long	0x2748774c,0xdf8eeb99,0x34b0bcb5,0xe19b48a8
	.long	0x391c0cb3,0xc5c95a63,0x4ed8aa4a,0xe3418acb
	.long	0x5b9cca4f,0x7763e373,0x682e6ff3,0xd6b2b8a3
	.long	0x748f82ee,0x5defb2fc,0x78a5636f,0x43172f60
	.long	0x84c87814,0xa1f0ab72,0x8cc70208,0x1a6439ec
	.long	0x90befffa,0x23631e28,0xa4506ceb,0xde82bde9
	.long	0xbef9a3f7,0xb2c67915,0xc67178f2,0xe372532b
	.long	0xca273ece,0xea26619c,0xd186b8c7,0x21c0c207
	.long	0xeada7dd6,0xcde0eb1e,0xf57d4f7f,0xee6ed178
	.long	0x06f067aa,0x72176fba,0x0a637dc5,0xa2c898a6
	.long	0x113f9804,0xbef90dae,0x1b710b35,0x131c471b
	.long	0x28db77f5,0x23047d84,0x32caab7b,0x40c72493
	.long	0x3c9ebe0a,0x15c9bebc,0x431d67c4,0x9c100d4c
	.long	0x4cc5d4be,0xcb3e42b6,0x597f299c,0xfc657e2a
	.long	0x5fcb6fab,0x3ad6faec,0x6c44198c,0x4a475817
___
$code.=<<___ if ($SZ==4);
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
