#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements support for AES instructions as per PowerISA
# specification version 2.07, first implemented by POWER8 processor.
# The module is endian-agnostic in sense that it supports both big-
# and little-endian cases. As well as alignment-agnostic, and it is
# guaranteed not to cause alignment exceptions. [One of options was
# to use VSX loads and stores, which tolerate unaligned references,
# but even then specification doesn't prohibit exceptions on page
# boundaries.]

$flavour = shift;

if ($flavour =~ /64/) {
	$SIZE_T	=8;
	$LRSAVE	=2*$SIZE_T;
	$STU	="stdu";
	$POP	="ld";
	$PUSH	="std";
} elsif ($flavour =~ /32/) {
	$SIZE_T	=4;
	$LRSAVE	=$SIZE_T;
	$STU	="stwu";
	$POP	="lwz";
	$PUSH	="stw";
} else { die "nonsense $flavour"; }

$LITTLE_ENDIAN = ($flavour=~/le$/) ? $SIZE_T : 0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour ".shift || die "can't call $xlate: $!";

$FRAME=8*$SIZE_T;
$prefix="AES";

$sp="r1";
$vrsave="r12";

{{{
my ($inp,$bits,$out,$ptr,$cnt,$rounds)=map("r$_",(3..8));
my ($zero,$in0,$in1,$key,$rcon,$mask,$tmp)=map("v$_",(0..6));
my ($stage,$outperm,$outmask,$outhead,$outtail)=map("v$_",(7..11));

$code.=<<___;
.machine	"any"

.text

.align	7
rcon:
.long	0x01000000, 0x01000000, 0x01000000, 0x01000000	?rev
.long	0x1b000000, 0x1b000000, 0x1b000000, 0x1b000000	?rev
.long	0x0d0e0f0c, 0x0d0e0f0c, 0x0d0e0f0c, 0x0d0e0f0c	?rev
.long	0,0,0,0						?asis
Lconsts:
	mflr	r0
	bcl	20,31,\$+4
	mflr	$ptr	 #vvvvv "distance between . and rcon
	addi	$ptr,$ptr,-0x48
	mtlr	r0
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
.asciz	"AES for PowerISA 2.07, CRYPTOGAMS by <appro\@openssl.org>"

.globl	.${prefix}_set_encrypt_key
.align	5
.${prefix}_set_encrypt_key:
Lset_encrypt_key:
	mflr		r11
	li		r0,0xfff
	$PUSH		r11,$LRSAVE($sp)
	mfspr		$vrsave,256
	mtspr		256,r0

	bl		Lconsts
	mtlr		r11

	neg		r9,$inp
	lvx		$in0,0,$inp
	addi		$inp,$inp,15		# 15 is not typo
	lvsr		$key,0,r9		# borrow $key
	li		r8,0x20
	cmpwi		$bits,192
	lvx		$in1,0,$inp
___
$code.=<<___		if ($LITTLE_ENDIAN);
	vspltisb	$mask,0x0f		# borrow $mask
	vxor		$key,$key,$mask		# adjust for byte swap
___
$code.=<<___;
	lvx		$rcon,0,$ptr
	lvx		$mask,r8,$ptr
	addi		$ptr,$ptr,0x10
	vperm		$in0,$in0,$in1,$key	# align [and byte swap in LE]
	li		$cnt,8
	vxor		$zero,$zero,$zero
	mtctr		$cnt

	?lvsr		$outperm,0,$out
	vspltisb	$outmask,-1
	lvx		$outhead,0,$out
	?vperm		$outmask,$zero,$outmask,$outperm

	blt		Loop128
	addi		$inp,$inp,8
	beq		L192
	addi		$inp,$inp,8
	b		L256

.align	4
Loop128:
	vperm		$key,$in0,$in0,$mask	# rotate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vcipherlast	$key,$key,$rcon
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	 vadduwm	$rcon,$rcon,$rcon
	vxor		$in0,$in0,$key
	bdnz		Loop128

	lvx		$rcon,0,$ptr		# last two round keys

	vperm		$key,$in0,$in0,$mask	# rotate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vcipherlast	$key,$key,$rcon
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	 vadduwm	$rcon,$rcon,$rcon
	vxor		$in0,$in0,$key

	vperm		$key,$in0,$in0,$mask	# rotate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vcipherlast	$key,$key,$rcon
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vxor		$in0,$in0,$key
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	 stvx		$stage,0,$out

	addi		$inp,$out,15		# 15 is not typo
	addi		$out,$out,0x50

	li		$rounds,10
	b		Ldone

.align	4
L192:
	lvx		$tmp,0,$inp
	li		$cnt,4
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	 stvx		$stage,0,$out
	 addi		$out,$out,16
	vperm		$in1,$in1,$tmp,$key	# align [and byte swap in LE]
	vspltisb	$key,8			# borrow $key
	mtctr		$cnt
	vsububm		$mask,$mask,$key	# adjust the mask

Loop192:
	vperm		$key,$in1,$in1,$mask	# roate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	vcipherlast	$key,$key,$rcon

	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp

	 vsldoi		$stage,$zero,$in1,8
	vspltw		$tmp,$in0,3
	vxor		$tmp,$tmp,$in1
	vsldoi		$in1,$zero,$in1,12	# >>32
	 vadduwm	$rcon,$rcon,$rcon
	vxor		$in1,$in1,$tmp
	vxor		$in0,$in0,$key
	vxor		$in1,$in1,$key
	 vsldoi		$stage,$stage,$in0,8

	vperm		$key,$in1,$in1,$mask	# rotate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	 vperm		$outtail,$stage,$stage,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vcipherlast	$key,$key,$rcon
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	 vsldoi		$stage,$in0,$in1,8
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	 vperm		$outtail,$stage,$stage,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	vspltw		$tmp,$in0,3
	vxor		$tmp,$tmp,$in1
	vsldoi		$in1,$zero,$in1,12	# >>32
	 vadduwm	$rcon,$rcon,$rcon
	vxor		$in1,$in1,$tmp
	vxor		$in0,$in0,$key
	vxor		$in1,$in1,$key
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	 stvx		$stage,0,$out
	 addi		$inp,$out,15		# 15 is not typo
	 addi		$out,$out,16
	bdnz		Loop192

	li		$rounds,12
	addi		$out,$out,0x20
	b		Ldone

.align	4
L256:
	lvx		$tmp,0,$inp
	li		$cnt,7
	li		$rounds,14
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	 stvx		$stage,0,$out
	 addi		$out,$out,16
	vperm		$in1,$in1,$tmp,$key	# align [and byte swap in LE]
	mtctr		$cnt

Loop256:
	vperm		$key,$in1,$in1,$mask	# rotate-n-splat
	vsldoi		$tmp,$zero,$in0,12	# >>32
	 vperm		$outtail,$in1,$in1,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	vcipherlast	$key,$key,$rcon
	 stvx		$stage,0,$out
	 addi		$out,$out,16

	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in0,$in0,$tmp
	 vadduwm	$rcon,$rcon,$rcon
	vxor		$in0,$in0,$key
	 vperm		$outtail,$in0,$in0,$outperm	# rotate
	 vsel		$stage,$outhead,$outtail,$outmask
	 vmr		$outhead,$outtail
	 stvx		$stage,0,$out
	 addi		$inp,$out,15		# 15 is not typo
	 addi		$out,$out,16
	bdz		Ldone

	vspltw		$key,$in0,3		# just splat
	vsldoi		$tmp,$zero,$in1,12	# >>32
	vsbox		$key,$key

	vxor		$in1,$in1,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in1,$in1,$tmp
	vsldoi		$tmp,$zero,$tmp,12	# >>32
	vxor		$in1,$in1,$tmp

	vxor		$in1,$in1,$key
	b		Loop256

.align	4
Ldone:
	lvx		$in1,0,$inp		# redundant in aligned case
	vsel		$in1,$outhead,$in1,$outmask
	stvx		$in1,0,$inp
	xor		r3,r3,r3		# return value
	mtspr		256,$vrsave
	stw		$rounds,0($out)

	blr
	.long		0
	.byte		0,12,0x14,1,0,0,3,0
.size	.${prefix}_set_encrypt_key,.-.${prefix}_set_encrypt_key

.globl	.${prefix}_set_decrypt_key
.align	5
.${prefix}_set_decrypt_key:
	$STU		$sp,-$FRAME($sp)
	mflr		r10
	$PUSH		r10,$FRAME+$LRSAVE($sp)
	bl		Lset_encrypt_key
	mtlr		r10

	slwi		$cnt,$rounds,4
	subi		$inp,$out,240		# first round key
	srwi		$rounds,$rounds,1
	add		$out,$inp,$cnt		# last round key
	mtctr		$rounds

Ldeckey:
	lwz		r0, 0($inp)
	lwz		r6, 4($inp)
	lwz		r7, 8($inp)
	lwz		r8, 12($inp)
	addi		$inp,$inp,16
	lwz		r9, 0($out)
	lwz		r10,4($out)
	lwz		r11,8($out)
	lwz		r12,12($out)
	stw		r0, 0($out)
	stw		r6, 4($out)
	stw		r7, 8($out)
	stw		r8, 12($out)
	subi		$out,$out,16
	stw		r9, -16($inp)
	stw		r10,-12($inp)
	stw		r11,-8($inp)
	stw		r12,-4($inp)
	bdnz		Ldeckey

	xor		r3,r3,r3		# return value
	addi		$sp,$sp,$FRAME
	blr
	.long		0
	.byte		0,12,4,1,0x80,0,3,0
.size	.${prefix}_set_decrypt_key,.-.${prefix}_set_decrypt_key
___
}}}
{{{
my ($inp,$out,$key,$rounds,$idx)=map("r$_",(3..7));

$code.=<<___;
.globl	.${prefix}_encrypt
.align	5
.${prefix}_encrypt:
	lwz		$rounds,240($key)
	li		r0,0x3f
	mfspr		$vrsave,256
	li		$idx,15			# 15 is not typo
	mtspr		256,r0

	lvx		v0,0,$inp
	neg		r11,$out
	lvx		v1,$idx,$inp
	lvsl		v2,0,$inp		# inpperm
	`"vspltisb	v4,0x0f"		if ($LITTLE_ENDIAN)`
	?lvsl		v3,0,r11		# outperm
	`"vxor		v2,v2,v4"		if ($LITTLE_ENDIAN)`
	li		$idx,16
	vperm		v0,v0,v1,v2		# align [and byte swap in LE]
	lvx		v1,0,$key
	?lvsl		v5,0,$key		# keyperm
	srwi		$rounds,$rounds,1
	lvx		v2,$idx,$key
	addi		$idx,$idx,16
	subi		$rounds,$rounds,1
	?vperm		v1,v1,v2,v5		# align round key

	vxor		v0,v0,v1
	lvx		v1,$idx,$key
	addi		$idx,$idx,16
	mtctr		$rounds

Loop_enc:
	?vperm		v2,v2,v1,v5
	vcipher		v0,v0,v2
	lvx		v2,$idx,$key
	addi		$idx,$idx,16
	?vperm		v1,v1,v2,v5
	vcipher		v0,v0,v1
	lvx		v1,$idx,$key
	addi		$idx,$idx,16
	bdnz		Loop_enc

	?vperm		v2,v2,v1,v5
	vcipher		v0,v0,v2
	lvx		v2,$idx,$key
	?vperm		v1,v1,v2,v5
	vcipherlast	v0,v0,v1

	vspltisb	v2,-1
	vxor		v1,v1,v1
	li		$idx,15			# 15 is not typo
	?vperm		v2,v1,v2,v3		# outmask
	`"vxor		v3,v3,v4"		if ($LITTLE_ENDIAN)`
	lvx		v1,0,$out		# outhead
	vperm		v0,v0,v0,v3		# rotate [and byte swap in LE]
	vsel		v1,v1,v0,v2
	lvx		v4,$idx,$out
	stvx		v1,0,$out
	vsel		v0,v0,v4,v2
	stvx		v0,$idx,$out

	mtspr		256,$vrsave
	blr
	.long		0
	.byte		0,12,0x14,0,0,0,3,0
.size	.${prefix}_encrypt,.-.${prefix}_encrypt

.globl	.${prefix}_decrypt
.align	5
.${prefix}_decrypt:
	lwz		$rounds,240($key)
	li		r0,0x3f
	mfspr		$vrsave,256
	li		$idx,15			# 15 is not typo
	mtspr		256,r0

	lvx		v0,0,$inp
	neg		r11,$out
	lvx		v1,$idx,$inp
	lvsl		v2,0,$inp		# inpperm
	`"vspltisb	v4,0x0f"		if ($LITTLE_ENDIAN)`
	?lvsl		v3,0,r11		# outperm
	`"vxor		v2,v2,v4"		if ($LITTLE_ENDIAN)`
	li		$idx,16
	vperm		v0,v0,v1,v2		# align [and byte swap in LE]
	lvx		v1,0,$key
	?lvsl		v5,0,$key		# keyperm
	srwi		$rounds,$rounds,1
	lvx		v2,$idx,$key
	addi		$idx,$idx,16
	subi		$rounds,$rounds,1
	?vperm		v1,v1,v2,v5		# align round key

	vxor		v0,v0,v1
	lvx		v1,$idx,$key
	addi		$idx,$idx,16
	mtctr		$rounds

Loop_dec:
	?vperm		v2,v2,v1,v5
	vncipher	v0,v0,v2
	lvx		v2,$idx,$key
	addi		$idx,$idx,16
	?vperm		v1,v1,v2,v5
	vncipher	v0,v0,v1
	lvx		v1,$idx,$key
	addi		$idx,$idx,16
	bdnz		Loop_dec

	?vperm		v2,v2,v1,v5
	vncipher	v0,v0,v2
	lvx		v2,$idx,$key
	?vperm		v1,v1,v2,v5
	vncipherlast	v0,v0,v1

	vspltisb	v2,-1
	vxor		v1,v1,v1
	li		$idx,15			# 15 is not typo
	?vperm		v2,v1,v2,v3		# outmask
	`"vxor		v3,v3,v4"		if ($LITTLE_ENDIAN)`
	lvx		v1,0,$out		# outhead
	vperm		v0,v0,v0,v3		# rotate [and byte swap in LE]
	vsel		v1,v1,v0,v2
	lvx		v4,$idx,$out
	stvx		v1,0,$out
	vsel		v0,v0,v4,v2
	stvx		v0,$idx,$out

	mtspr		256,$vrsave
	blr
	.long		0
	.byte		0,12,0x14,0,0,0,3,0
.size	.${prefix}_decrypt,.-.${prefix}_decrypt
___
}}}
{{{
my ($inp,$out,$len,$key,$ivp,$enc,$rounds,$idx)=map("r$_",(3..10));
my ($rndkey0,$rndkey1,$inout,$ivec,$tmp)=map("v$_",(0..4));
my ($inptail,$inpperm,$outhead,$outperm,$outmask,$keyperm)=map("v$_",(5..10));

$code.=<<___;
.globl	.${prefix}_cbc_encrypt
.align	5
.${prefix}_cbc_encrypt:
	subic.		$len,$len,16
	bltlr-

	cmpwi		$enc,0			# test direction
	li		r0,0x7ff
	mfspr		$vrsave,256
	mtspr		256,r0

	li		$idx,15
	vxor		$rndkey0,$rndkey0,$rndkey0
	`"vspltisb	$tmp,0x0f"		if ($LITTLE_ENDIAN)`

	lvx		$ivec,0,$ivp		# load [unaligned] iv
	lvsl		$inpperm,0,$ivp
	lvx		$inptail,$idx,$ivp
	`"vxor		$inpperm,$inpperm,$tmp"	if ($LITTLE_ENDIAN)`
	vperm		$ivec,$ivec,$inptail,$inpperm

	?lvsl		$keyperm,0,$key		# prepare for unaligned key
	lwz		$rounds,240($key)

	lvsl		$inpperm,0,$inp		# prepare for unaligned load
	lvx		$inptail,0,$inp
	addi		$inp,$inp,15		# 15 is not typo
	`"vxor		$inpperm,$inpperm,$tmp"	if ($LITTLE_ENDIAN)`

	?lvsr		$outperm,0,$out		# prepare for unaligned store
	vspltisb	$outmask,-1
	lvx		$outhead,0,$out
	?vperm		$outmask,$rndkey0,$outmask,$outperm
	`"vxor		$outperm,$outperm,$tmp"	if ($LITTLE_ENDIAN)`

	srwi		$rounds,$rounds,1
	li		$idx,16
	subi		$rounds,$rounds,1
	beq		Lcbc_dec

Lcbc_enc:
	vmr		$inout,$inptail
	lvx		$inptail,0,$inp
	addi		$inp,$inp,16
	mtctr		$rounds

	lvx		$rndkey0,0,$key
	 vperm		$inout,$inout,$inptail,$inpperm
	lvx		$rndkey1,$idx,$key
	addi		$idx,$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vxor		$inout,$inout,$rndkey0
	lvx		$rndkey0,$idx,$key
	addi		$idx,$idx,16
	vxor		$inout,$inout,$ivec

Loop_cbc_enc:
	?vperm		$rndkey1,$rndkey1,$rndkey0,$keyperm
	vcipher		$inout,$inout,$rndkey1
	lvx		$rndkey1,$idx,$key
	addi		$idx,$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vcipher		$inout,$inout,$rndkey0
	lvx		$rndkey0,$idx,$key
	addi		$idx,$idx,16
	bdnz		Loop_cbc_enc

	?vperm		$rndkey1,$rndkey1,$rndkey0,$keyperm
	vcipher		$inout,$inout,$rndkey1
	lvx		$rndkey1,$idx,$key
	li		$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vcipherlast	$ivec,$inout,$rndkey0
	sub.		$len,$len,$idx		# len -=16

	vperm		$tmp,$ivec,$ivec,$outperm
	vsel		$inout,$outhead,$tmp,$outmask
	vmr		$outhead,$tmp
	stvx		$inout,0,$out
	addi		$out,$out,16
	bge		Lcbc_enc

	b		Lcbc_done

.align	4
Lcbc_dec:
	vmr		$tmp,$inptail
	lvx		$inptail,0,$inp
	addi		$inp,$inp,16
	mtctr		$rounds

	lvx		$rndkey0,0,$key
	 vperm		$tmp,$tmp,$inptail,$inpperm
	lvx		$rndkey1,$idx,$key
	addi		$idx,$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vxor		$inout,$tmp,$rndkey0
	lvx		$rndkey0,$idx,$key
	addi		$idx,$idx,16

Loop_cbc_dec:
	?vperm		$rndkey1,$rndkey1,$rndkey0,$keyperm
	vncipher	$inout,$inout,$rndkey1
	lvx		$rndkey1,$idx,$key
	addi		$idx,$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vncipher	$inout,$inout,$rndkey0
	lvx		$rndkey0,$idx,$key
	addi		$idx,$idx,16
	bdnz		Loop_cbc_dec

	?vperm		$rndkey1,$rndkey1,$rndkey0,$keyperm
	vncipher	$inout,$inout,$rndkey1
	lvx		$rndkey1,$idx,$key
	li		$idx,16
	?vperm		$rndkey0,$rndkey0,$rndkey1,$keyperm
	vncipherlast	$inout,$inout,$rndkey0
	sub.		$len,$len,$idx		# len -=16

	vxor		$inout,$inout,$ivec
	vmr		$ivec,$tmp
	vperm		$tmp,$inout,$inout,$outperm
	vsel		$inout,$outhead,$tmp,$outmask
	vmr		$outhead,$tmp
	stvx		$inout,0,$out
	addi		$out,$out,16
	bge		Lcbc_dec

Lcbc_done:
	addi		$out,$out,-1
	lvx		$inout,0,$out		# redundant in aligned case
	vsel		$inout,$outhead,$inout,$outmask
	stvx		$inout,0,$out

	neg		$enc,$ivp		# write [unaligned] iv
	li		$idx,15			# 15 is not typo
	vxor		$rndkey0,$rndkey0,$rndkey0
	vspltisb	$outmask,-1
	`"vspltisb	$tmp,0x0f"		if ($LITTLE_ENDIAN)`
	?lvsl		$outperm,0,$enc
	?vperm		$outmask,$rndkey0,$outmask,$outperm
	`"vxor		$outperm,$outperm,$tmp"	if ($LITTLE_ENDIAN)`
	lvx		$outhead,0,$ivp
	vperm		$ivec,$ivec,$ivec,$outperm
	vsel		$inout,$outhead,$ivec,$outmask
	lvx		$inptail,$idx,$ivp
	stvx		$inout,0,$ivp
	vsel		$inout,$ivec,$inptail,$outmask
	stvx		$inout,$idx,$ivp

	mtspr		256,$vrsave
	blr
	.long		0
	.byte		0,12,0x14,0,0,0,6,0
.size	.${prefix}_cbc_encrypt,.-.${prefix}_cbc_encrypt
___
}}}

my $consts=1;
foreach(split("\n",$code)) {
        s/\`([^\`]*)\`/eval($1)/geo;

	# constants table endian-specific conversion
	if ($consts && m/\.(long|byte)\s+(.+)\s+(\?[a-z]*)$/o) {
	    my $conv=$3;
	    my @bytes=();

	    # convert to endian-agnostic format
	    if ($1 eq "long") {
	      foreach (split(/,\s*/,$2)) {
		my $l = /^0/?oct:int;
		push @bytes,($l>>24)&0xff,($l>>16)&0xff,($l>>8)&0xff,$l&0xff;
	      }
	    } else {
		@bytes = map(/^0/?oct:int,split(/,\s*/,$2));
	    }

	    # little-endian conversion
	    if ($flavour =~ /le$/o) {
		SWITCH: for($conv)  {
		    /\?inv/ && do   { @bytes=map($_^0xf,@bytes); last; };
		    /\?rev/ && do   { @bytes=reverse(@bytes);    last; }; 
		}
	    }

	    #emit
	    print ".byte\t",join(',',map (sprintf("0x%02x",$_),@bytes)),"\n";
	    next;
	}
	$consts=0 if (m/Lconsts:/o);	# end of table

	# instructions prefixed with '?' are endian-specific and need
	# to be adjusted accordingly...
	if ($flavour =~ /le$/o) {	# little-endian
	    s/\?lvsr/lvsl/o or
	    s/\?lvsl/lvsr/o or
	    s/\?(vperm\s+v[0-9]+,\s*)(v[0-9]+,\s*)(v[0-9]+,\s*)(v[0-9]+)/$1$3$2$4/o or
	    s/\?(vsldoi\s+v[0-9]+,\s*)(v[0-9]+,)\s*(v[0-9]+,\s*)([0-9]+)/$1$3$2 16-$4/o or
	    s/\?(vspltw\s+v[0-9]+,\s*)(v[0-9]+,)\s*([0-9])/$1$2 3-$3/o;
	} else {			# big-endian
	    s/\?([a-z]+)/$1/o;
	}

        print $_,"\n";
}

close STDOUT;
