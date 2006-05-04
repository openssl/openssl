#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================

# April 2006

# "Teaser" Montgomery multiplication module for PowerPC. It's possible
# to gain a bit more by modulo-scheduling outer loop, then dedicated
# squaring procedure should give further 20% and code can be adapted
# for 32-bit application running on 64-bit CPU. As for the latter.
# It won't be able to achieve "native" 64-bit performance, because in
# 32-bit application context every addc instruction will have to be
# expanded as addc, twice right shift by 32 and finally adde, etc.
# So far RSA *sign* performance improvement over pre-bn_mul_mont asm
# for 64-bit application running on PPC970/G5 is:
#
# 512-bit	+65%	
# 1024-bit	+35%
# 2048-bit	+18%
# 4096-bit	+4%

$output = shift;

if ($output =~ /32\-mont\.s/) {
	$BITS=	32;
	$BNSZ=	$BITS/8;
	$SIZE_T=4;
	$RZONE=	224;
	$FRAME=	$SIZE_T*16;

	$LD=	"lwz";		# load
	$LDU=	"lwzu";		# load and update
	$LDX=	"lwzx";		# load indexed
	$ST=	"stw";		# store
	$STU=	"stwu";		# store and update
	$STX=	"stwx";		# store indexed
	$STUX=	"stwux";	# store indexed and update
	$UMULL=	"mullw";	# unsigned multiply low
	$UMULH=	"mulhwu";	# unsigned multiply high
	$UCMP=	"cmplw";	# unsigned compare
	$PUSH=	$ST;
	$POP=	$LD;
} elsif ($output =~ /64\-mont\.s/) {
	$BITS=	64;
	$BNSZ=	$BITS/8;
	$SIZE_T=8;
	$RZONE=	288;
	$FRAME=	$SIZE_T*16;

	# same as above, but 64-bit mnemonics...
	$LD=	"ld";		# load
	$LDU=	"ldu";		# load and update
	$LDX=	"ldx";		# load indexed
	$ST=	"std";		# store
	$STU=	"stdu";		# store and update
	$STX=	"stdx";		# store indexed
	$STUX=	"stdux";	# store indexed and update
	$UMULL=	"mulld";	# unsigned multiply low
	$UMULH=	"mulhdu";	# unsigned multiply high
	$UCMP=	"cmpld";	# unsigned compare
	$PUSH=	$ST;
	$POP=	$LD;
} else { die "nonsense $output"; }

( defined shift || open STDOUT,"| $^X ../perlasm/ppc-xlate.pl $output" ) ||
	die "can't call ../perlasm/ppc-xlate.pl: $!";

$sp="r1";
$toc="r2";
$rp="r3";	$ovf="r3";
$ap="r4";
$bp="r5";
$np="r6";
$n0="r7";
$num="r8";
$rp="r9";	# $rp is reassigned
$aj="r10";
$nj="r11";
$tj="r12";
# non-volatile registers
$i="r14";
$j="r15";
$tp="r16";
$m0="r17";
$m1="r18";
$lo0="r19";
$hi0="r20";
$lo1="r21";
$hi1="r22";
$alo="r23";
$ahi="r24";
$nlo="r25";
#
$nhi="r0";

$code=<<___;
.machine "any"
.text

.globl	.bn_mul_mont
.align	4
.bn_mul_mont:
	cmpwi	$num,4
	mr	$rp,r3		; $rp is reassigned
	li	r3,0
	bltlr

	slwi	$num,$num,`log($BNSZ)/log(2)`
	li	$tj,-4096
	addi	$ovf,$num,`$FRAME+$RZONE`
	subf	$ovf,$ovf,$sp	; $sp-$ovf
	and	$ovf,$ovf,$tj	; minimize TLB usage
	subf	$ovf,$sp,$ovf	; $ovf-$sp
	srwi	$num,$num,`log($BNSZ)/log(2)`
	$STUX	$sp,$sp,$ovf

	$PUSH	r14,`4*$SIZE_T`($sp)
	$PUSH	r15,`5*$SIZE_T`($sp)
	$PUSH	r16,`6*$SIZE_T`($sp)
	$PUSH	r17,`7*$SIZE_T`($sp)
	$PUSH	r18,`8*$SIZE_T`($sp)
	$PUSH	r19,`9*$SIZE_T`($sp)
	$PUSH	r20,`10*$SIZE_T`($sp)
	$PUSH	r21,`11*$SIZE_T`($sp)
	$PUSH	r22,`12*$SIZE_T`($sp)
	$PUSH	r23,`13*$SIZE_T`($sp)
	$PUSH	r24,`14*$SIZE_T`($sp)
	$PUSH	r25,`15*$SIZE_T`($sp)

	$LD	$n0,0($n0)	; pull n0[0] value
	addi	$num,$num,-2	; adjust $num for counter register

	$LD	$m0,0($bp)	; m0=bp[0]
	$LD	$aj,0($ap)	; ap[0]
	addi	$tp,$sp,$FRAME
	$UMULL	$lo0,$aj,$m0	; ap[0]*bp[0]
	$UMULH	$hi0,$aj,$m0

	$LD	$aj,$BNSZ($ap)	; ap[1]
	$LD	$nj,0($np)	; np[0]

	$UMULL	$m1,$lo0,$n0	; "tp[0]"*n0

	$UMULL	$alo,$aj,$m0	; ap[1]*bp[0]
	$UMULH	$ahi,$aj,$m0

	$UMULL	$lo1,$nj,$m1	; np[0]*m1
	$UMULH	$hi1,$nj,$m1
	$LD	$nj,$BNSZ($np)	; np[1]
	addc	$lo1,$lo1,$lo0
	addze	$hi1,$hi1

	$UMULL	$nlo,$nj,$m1	; np[1]*m1
	$UMULH	$nhi,$nj,$m1

	mtctr	$num
	li	$j,`2*$BNSZ`
.align	4
L1st:
	$LDX	$aj,$ap,$j	; ap[j]
	$LDX	$nj,$np,$j	; np[j]
	addc	$lo0,$alo,$hi0
	addze	$hi0,$ahi
	$UMULL	$alo,$aj,$m0	; ap[j]*bp[0]
	$UMULH	$ahi,$aj,$m0

	addc	$lo1,$nlo,$hi1
	addze	$hi1,$nhi
	$UMULL	$nlo,$nj,$m1	; np[j]*m1
	$UMULH	$nhi,$nj,$m1
	addc	$lo1,$lo1,$lo0	; np[j]*m1+ap[j]*bp[0]
	addze	$hi1,$hi1
	$ST	$lo1,0($tp)	; tp[j-1]

	addi	$j,$j,$BNSZ	; j++
	addi	$tp,$tp,$BNSZ	; tp++
	bdnz-	L1st
;L1st
	addc	$lo0,$alo,$hi0
	addze	$hi0,$ahi

	addc	$lo1,$nlo,$hi1
	addze	$hi1,$nhi
	addc	$lo1,$lo1,$lo0	; np[j]*m1+ap[j]*bp[0]
	addze	$hi1,$hi1
	$ST	$lo1,0($tp)	; tp[j-1]

	li	$ovf,0
	addc	$hi1,$hi1,$hi0
	addze	$ovf,$ovf	; upmost overflow bit
	$ST	$hi1,$BNSZ($tp)

	li	$i,$BNSZ
.align	4
Louter:
	$LDX	$m0,$bp,$i	; m0=bp[i]
	$LD	$aj,0($ap)	; ap[0]
	addi	$tp,$sp,$FRAME
	$LD	$tj,$FRAME($sp)	; tp[0]
	$UMULL	$lo0,$aj,$m0	; ap[0]*bp[i]
	$UMULH	$hi0,$aj,$m0
	$LD	$aj,$BNSZ($ap)	; ap[1]
	$LD	$nj,0($np)	; np[0]
	addc	$lo0,$lo0,$tj	; ap[0]*bp[i]+tp[0]
	addze	$hi0,$hi0

	$UMULL	$m1,$lo0,$n0	; tp[0]*n0

	$UMULL	$alo,$aj,$m0	; ap[j]*bp[i]
	$UMULH	$ahi,$aj,$m0

	$UMULL	$lo1,$nj,$m1	; np[0]*m1
	$UMULH	$hi1,$nj,$m1
	$LD	$nj,$BNSZ($np)	; np[1]
	addc	$lo1,$lo1,$lo0
	addze	$hi1,$hi1

	$UMULL	$nlo,$nj,$m1	; np[1]*m1
	$UMULH	$nhi,$nj,$m1

	mtctr	$num
	li	$j,`2*$BNSZ`
.align	4
Linner:
	$LDX	$aj,$ap,$j	; ap[j]
	$LD	$tj,$BNSZ($tp)	; tp[j]
	addc	$lo0,$alo,$hi0
	addze	$hi0,$ahi
	$LDX	$nj,$np,$j	; np[j]
	addc	$lo0,$lo0,$tj	; ap[j]*bp[i]+tp[j]
	addze	$hi0,$hi0
	$UMULL	$alo,$aj,$m0	; ap[j]*bp[i]
	$UMULH	$ahi,$aj,$m0

	addc	$lo1,$nlo,$hi1
	addze	$hi1,$nhi
	$UMULL	$nlo,$nj,$m1	; np[j]*m1
	$UMULH	$nhi,$nj,$m1
	addc	$lo1,$lo1,$lo0	; np[j]*m1+ap[j]*bp[i]+tp[j]
	addze	$hi1,$hi1
	$ST	$lo1,0($tp)	; tp[j-1]

	addi	$j,$j,$BNSZ	; j++
	addi	$tp,$tp,$BNSZ	; tp++
	bdnz-	Linner
;Linner
	$LD	$tj,$BNSZ($tp)	; tp[j]
	addc	$lo0,$alo,$hi0
	addze	$hi0,$ahi
	addc	$lo0,$lo0,$tj	; ap[j]*bp[i]+tp[j]
	addze	$hi0,$hi0

	addc	$lo1,$nlo,$hi1
	addze	$hi1,$nhi
	addc	$lo1,$lo1,$lo0	; np[j]*m1+ap[j]*bp[i]+tp[j]
	addze	$hi1,$hi1
	$ST	$lo1,0($tp)	; tp[j-1]

	addic	$ovf,$ovf,-1	; move upmost overflow to XER[CA]
	li	$ovf,0
	adde	$hi1,$hi1,$hi0
	addze	$ovf,$ovf
	$ST	$hi1,$BNSZ($tp)
;
	slwi	$tj,$num,`log($BNSZ)/log(2)`
	$UCMP	$i,$tj
	addi	$i,$i,$BNSZ
	ble-	Louter

	addi	$num,$num,2	; restore $num
	addi	$tp,$sp,$FRAME
	mtctr	$num
	li	$j,0

	subfc.	$ovf,$j,$ovf	; sets XER[CA]
	bne	Lsub
	$UCMP	$hi1,$nj
	bge	Lsub
.align	4
Lcopy:
	$LDX	$tj,$tp,$j
	$STX	$tj,$rp,$j
	$STX	$j,$tp,$j	; zap at once
	addi	$j,$j,$BNSZ
	bdnz-	Lcopy

Lexit:
	$POP	r14,`4*$SIZE_T`($sp)
	$POP	r15,`5*$SIZE_T`($sp)
	$POP	r16,`6*$SIZE_T`($sp)
	$POP	r17,`7*$SIZE_T`($sp)
	$POP	r18,`8*$SIZE_T`($sp)
	$POP	r19,`9*$SIZE_T`($sp)
	$POP	r20,`10*$SIZE_T`($sp)
	$POP	r21,`11*$SIZE_T`($sp)
	$POP	r22,`12*$SIZE_T`($sp)
	$POP	r23,`13*$SIZE_T`($sp)
	$POP	r24,`14*$SIZE_T`($sp)
	$POP	r25,`15*$SIZE_T`($sp)
	$POP	$sp,0($sp)
	li	r3,1
	blr
	.long	0
.align	4
Lsub:	$LDX	$tj,$tp,$j
	$LDX	$nj,$np,$j
	subfe	$tj,$nj,$tj	; tp[j]-np[j]
	$STX	$tj,$rp,$j
	addi	$j,$j,$BNSZ
	bdnz-	Lsub
	li	$j,0
	subfe.	$ovf,$j,$ovf
	mtctr	$num
	bne	Lcopy
.align	4
Lzap:	$STX	$j,$tp,$j
	addi	$j,$j,$BNSZ
	bdnz-	Lzap
	b	Lexit
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
