#!/usr/bin/env perl

# ====================================================================
# Written by David S. Miller <davem@devemloft.net> and Andy Polyakov
# <appro@openssl.org>. The module is licensed under 2-clause BSD
# license. October 2012. All rights reserved.
# ====================================================================

######################################################################
# AES round instructions complete in 3 cycles and can be issued every
# cycle. It means that round calculations should take 4*rounds cycles,
# because any given round instruction depends on result of *both*
# previous instructions:
#
#	|0 |1 |2 |3 |4
#	|01|01|01|
#	   |23|23|23|
#	            |01|01|...
#	               |23|...
#
# Provided that fxor [with IV] takes 3 cycles to complete, critical
# path length for CBC encrypt would be 3+4*rounds, or in other words
# it should process one byte in at least (3+4*rounds)/16 cycles. This
# estimate doesn't account for "collateral" instructions, such as
# fetching input from memory, xor-ing it with zero-round key and
# storing the result. Yet, *measured* performance [for data aligned
# at 64-bit boundary!] deviates from this equation by less than 0.5%:
#
#		128-bit key	192-		256-
# CBC encrypt	2.70/2.90(*)	3.20/3.40	3.70/3.90
#			 (*) numbers after slash are for
#			     misaligned data.
#
# Out-of-order execution logic managed to fully overlap "collateral"
# instructions with those on critical path. Amazing!
#
# As with Intel AES-NI, question is if it's possible to improve
# performance of parallelizeable modes by interleaving round
# instructions. Provided round instruction latency and throughput
# optimal interleave factor is 2. But can we expect 2x performance
# improvement? Well, as round instructions can be issued one per
# cycle, they don't saturate the 2-way issue pipeline and therefore
# there is room for "collateral" calculations... Yet, 2x speed-up
# over CBC encrypt remains unattaintable:
#
#		128-bit key	192-		256-
# CBC decrypt	1.64/2.11	1.89/2.37	2.23/2.61
# CTR		1.64/2.08(*)	1.89/2.33	2.23/2.61
#			 (*) numbers after slash are for
#			     misaligned data.
#
# Estimates based on amount of instructions under assumption that
# round instructions are not pairable with any other instruction
# suggest that latter is the actual case and pipeline runs
# underutilized. It should be noted that T4 out-of-order execution
# logic is so capable that performance gain from 2x interleave is
# not even impressive, ~7-13% over non-interleaved code, largest
# for 256-bit keys.

# To anchor to something else, software implementation processes
# one byte in 29 cycles with 128-bit key on same processor. Intel
# Sandy Bridge encrypts byte in 5.07 cycles in CBC mode and decrypts
# in 0.93, naturally with AES-NI.

$bits=32;
for (@ARGV)     { $bits=64 if (/\-m64/ || /\-xarch\=v9/); }
if ($bits==64)  { $bias=2047; $frame=192; }
else            { $bias=0;    $frame=112; }

$evp=1;		# if $evp is set to 0, script generates module with
# AES_[en|de]crypt, AES_set_[en|de]crypt_key and AES_cbc_encrypt entry
# points. These however are not fully compatible with openssl/aes.h,
# because they expect AES_KEY to be aligned at 64-bit boundary. When
# used through EVP, alignment is arranged at EVP layer. Second thing
# that is arranged by EVP is at least 32-bit alignment of IV.

######################################################################
# single-round subroutines
#
{
my ($inp,$out,$key,$rounds,$tmp,$mask)=map("%o$_",(0..5));

$code=<<___;
.text

.globl	aes_t4_encrypt
.align	32
aes_t4_encrypt:
	andcc		$inp, 7, %g1		! is input aligned?
	andn		$inp, 7, $inp

	ldx		[$key + 0], %g4
	ldx		[$key + 8], %g5

	ldx		[$inp + 0], %o4
	bz,pt		%icc, 1f
	ldx		[$inp + 8], %o5
	ldx		[$inp + 16], $inp
	sll		%g1, 3, %g1
	sub		%g0, %g1, %o3
	sllx		%o4, %g1, %o4
	sllx		%o5, %g1, %g1
	srlx		%o5, %o3, %o5
	srlx		$inp, %o3, %o3
	or		%o5, %o4, %o4
	or		%o3, %g1, %o5
1:
	ld		[$key + 240], $rounds
	ldd		[$key + 16], %f12
	ldd		[$key + 24], %f14
	xor		%g4, %o4, %o4
	xor		%g5, %o5, %o5
	movxtod		%o4, %f0
	movxtod		%o5, %f2
	srl		$rounds, 1, $rounds
	ldd		[$key + 32], %f16
	sub		$rounds, 1, $rounds
	ldd		[$key + 40], %f18
	add		$key, 48, $key

.Lenc:
	aes_eround01	%f12, %f0, %f2, %f4
	aes_eround23	%f14, %f0, %f2, %f2
	ldd		[$key + 0], %f12
	ldd		[$key + 8], %f14
	sub		$rounds,1,$rounds
	aes_eround01	%f16, %f4, %f2, %f0
	aes_eround23	%f18, %f4, %f2, %f2
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	brnz,pt		$rounds, .Lenc
	add		$key, 32, $key

	andcc		$out, 7, $tmp		! is output aligned?
	aes_eround01	%f12, %f0, %f2, %f4
	aes_eround23	%f14, %f0, %f2, %f2
	aes_eround01_l	%f16, %f4, %f2, %f0
	aes_eround23_l	%f18, %f4, %f2, %f2

	bnz,pn		%icc, 2f
	nop

	std		%f0, [$out + 0]
	retl
	std		%f2, [$out + 8]

2:	alignaddrl	$out, %g0, $out
	mov		0xff, $mask
	srl		$mask, $tmp, $mask

	faligndata	%f0, %f0, %f4
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $mask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $mask, $mask
	retl
	stda		%f8, [$out + $mask]0xc0	! partial store
.type	aes_t4_encrypt,#function
.size	aes_t4_encrypt,.-aes_t4_encrypt

.globl	aes_t4_decrypt
.align	32
aes_t4_decrypt:
	andcc		$inp, 7, %g1		! is input aligned?
	andn		$inp, 7, $inp

	ldx		[$key + 0], %g4
	ldx		[$key + 8], %g5

	ldx		[$inp + 0], %o4
	bz,pt		%icc, 1f
	ldx		[$inp + 8], %o5
	ldx		[$inp + 16], $inp
	sll		%g1, 3, %g1
	sub		%g0, %g1, %o3
	sllx		%o4, %g1, %o4
	sllx		%o5, %g1, %g1
	srlx		%o5, %o3, %o5
	srlx		$inp, %o3, %o3
	or		%o5, %o4, %o4
	or		%o3, %g1, %o5
1:
	ld		[$key + 240], $rounds
	ldd		[$key + 16], %f12
	ldd		[$key + 24], %f14
	xor		%g4, %o4, %o4
	xor		%g5, %o5, %o5
	movxtod		%o4, %f0
	movxtod		%o5, %f2
	srl		$rounds, 1, $rounds
	ldd		[$key + 32], %f16
	sub		$rounds, 1, $rounds
	ldd		[$key + 40], %f18
	add		$key, 48, $key

.Ldec:
	aes_dround01	%f12, %f0, %f2, %f4
	aes_dround23	%f14, %f0, %f2, %f2
	ldd		[$key + 0], %f12
	ldd		[$key + 8], %f14
	sub		$rounds,1,$rounds
	aes_dround01	%f16, %f4, %f2, %f0
	aes_dround23	%f18, %f4, %f2, %f2
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	brnz,pt		$rounds, .Ldec
	add		$key, 32, $key

	andcc		$out, 7, $tmp		! is output aligned?
	aes_dround01	%f12, %f0, %f2, %f4
	aes_dround23	%f14, %f0, %f2, %f2
	aes_dround01_l	%f16, %f4, %f2, %f0
	aes_dround23_l	%f18, %f4, %f2, %f2

	bnz,pn		%icc, 2f
	nop

	std		%f0, [$out + 0]
	retl
	std		%f2, [$out + 8]

2:	alignaddrl	$out, %g0, $out
	mov		0xff, $mask
	srl		$mask, $tmp, $mask

	faligndata	%f0, %f0, %f4
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $mask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $mask, $mask
	retl
	stda		%f8, [$out + $mask]0xc0	! partial store
.type	aes_t4_decrypt,#function
.size	aes_t4_decrypt,.-aes_t4_decrypt
___
}

######################################################################
# key setup subroutines
#
{
my ($inp,$bits,$out,$tmp)=map("%o$_",(0..5));
$code.=<<___;
.globl	aes_t4_set_encrypt_key
.align	32
aes_t4_set_encrypt_key:
.Lset_encrypt_key:
	and		$inp, 7, $tmp
	alignaddr	$inp, %g0, $inp
	cmp		$bits, 192
	ldd		[$inp + 0], %f0
	bl,pt		%icc,.L128
	ldd		[$inp + 8], %f2

	be,pt		%icc,.L192
	ldd		[$inp + 16], %f4
	brz,pt		$tmp, .L256aligned
	ldd		[$inp + 24], %f6

	ldd		[$inp + 32], %f8
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4
	faligndata	%f6, %f8, %f6
.L256aligned:
___
for ($i=0; $i<6; $i++) {
    $code.=<<___;
	std		%f0, [$out + `32*$i+0`]
	aes_kexpand1	%f0, %f6, $i, %f0
	std		%f2, [$out + `32*$i+8`]
	aes_kexpand2	%f2, %f0, %f2
	std		%f4, [$out + `32*$i+16`]
	aes_kexpand0	%f4, %f2, %f4
	std		%f6, [$out + `32*$i+24`]
	aes_kexpand2	%f6, %f4, %f6
___
}
$code.=<<___;
	std		%f0, [$out + `32*$i+0`]
	aes_kexpand1	%f0, %f6, $i, %f0
	std		%f2, [$out + `32*$i+8`]
	aes_kexpand2	%f2, %f0, %f2
	std		%f4, [$out + `32*$i+16`]
	std		%f6, [$out + `32*$i+24`]
	std		%f0, [$out + `32*$i+32`]
	std		%f2, [$out + `32*$i+40`]

	mov		14, $tmp
	st		$tmp, [$out + 240]
	retl
	xor		%o0, %o0, %o0

.align	16
.L192:
	brz,pt		$tmp, .L192aligned
	nop

	ldd		[$inp + 24], %f6
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4
.L192aligned:
___
for ($i=0; $i<7; $i++) {
    $code.=<<___;
	std		%f0, [$out + `24*$i+0`]
	aes_kexpand1	%f0, %f4, $i, %f0
	std		%f2, [$out + `24*$i+8`]
	aes_kexpand2	%f2, %f0, %f2
	std		%f4, [$out + `24*$i+16`]
	aes_kexpand2	%f4, %f2, %f4
___
}
$code.=<<___;
	std		%f0, [$out + `24*$i+0`]
	aes_kexpand1	%f0, %f4, $i, %f0
	std		%f2, [$out + `24*$i+8`]
	aes_kexpand2	%f2, %f0, %f2
	std		%f4, [$out + `24*$i+16`]
	std		%f0, [$out + `24*$i+24`]
	std		%f2, [$out + `24*$i+32`]

	mov		12, $tmp
	st		$tmp, [$out + 240]
	retl
	xor		%o0, %o0, %o0

.align	16
.L128:
	brz,pt		$tmp, .L128aligned
	nop

	ldd		[$inp + 16], %f4
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
.L128aligned:
___
for ($i=0; $i<10; $i++) {
    $code.=<<___;
	std		%f0, [$out + `16*$i+0`]
	aes_kexpand1	%f0, %f2, $i, %f0
	std		%f2, [$out + `16*$i+8`]
	aes_kexpand2	%f2, %f0, %f2
___
}
$code.=<<___;
	std		%f0, [$out + `16*$i+0`]
	std		%f2, [$out + `16*$i+8`]

	mov		10, $tmp
	st		$tmp, [$out + 240]
	retl
	xor		%o0, %o0, %o0
.type	aes_t4_set_encrypt_key,#function
.size	aes_t4_set_encrypt_key,.-aes_t4_set_encrypt_key

.globl	aes_t4_set_decrypt_key
.align	32
aes_t4_set_decrypt_key:
	mov		%o7, %o5
	call		.Lset_encrypt_key
	nop

	mov		%o5, %o7
	sll		$tmp, 4, $inp		! $tmp is number of rounds
	add		$tmp, 2, $tmp
	add		$out, $inp, $inp	! $inp=$out+16*rounds
	srl		$tmp, 2, $tmp		! $tmp=(rounds+2)/4

.Lkey_flip:
	ldd		[$out + 0],  %f0
	ldd		[$out + 8],  %f2
	ldd		[$out + 16], %f4
	ldd		[$out + 24], %f6
	ldd		[$inp + 0],  %f8
	ldd		[$inp + 8],  %f10
	ldd		[$inp - 16], %f12
	ldd		[$inp - 8],  %f14
	sub		$tmp, 1, $tmp
	std		%f0, [$inp + 0]
	std		%f2, [$inp + 8]
	std		%f4, [$inp - 16]
	std		%f6, [$inp - 8]
	std		%f8, [$out + 0]
	std		%f10, [$out + 8]
	std		%f12, [$out + 16]
	std		%f14, [$out + 24]
	add		$out, 32, $out
	brnz		$tmp, .Lkey_flip
	sub		$inp, 32, $inp

	retl
	xor		%o0, %o0, %o0
.type	aes_t4_set_decrypt_key,#function
.size	aes_t4_set_decrypt_key,.-aes_t4_set_decrypt_key
___
}

{{{
my ($inp,$out,$len,$key,$ivec,$enc)=map("%i$_",(0..5));
my ($ileft,$iright,$ooff,$omask,$ivoff)=map("%l$_",(1..7));

$code.=<<___;
.align	32
_aes128_loadkey:
	ldx		[$key + 0], %g4
	ldx		[$key + 8], %g5
___
for ($i=2; $i<22;$i++) {			# load key schedule
    $code.=<<___;
	ldd		[$key + `8*$i`], %f`12+2*$i`
___
}
$code.=<<___;
	retl
	nop
.type	_aes128_loadkey,#function
.size	_aes128_loadkey,.-_aes128_loadkey

.align	32
_aes128_encrypt_1x:
___
for ($i=0; $i<4; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_eround01	%f48, %f0, %f2, %f4
	aes_eround23	%f50, %f0, %f2, %f2
	aes_eround01_l	%f52, %f4, %f2, %f0
	retl
	aes_eround23_l	%f54, %f4, %f2, %f2
.type	_aes128_encrypt_1x,#function
.size	_aes128_encrypt_1x,.-_aes128_encrypt_1x

.align	32
_aes128_encrypt_2x:
___
for ($i=0; $i<4; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_eround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_eround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_eround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_eround01	%f48, %f0, %f2, %f8
	aes_eround23	%f50, %f0, %f2, %f2
	aes_eround01	%f48, %f4, %f6, %f10
	aes_eround23	%f50, %f4, %f6, %f6
	aes_eround01_l	%f52, %f8, %f2, %f0
	aes_eround23_l	%f54, %f8, %f2, %f2
	aes_eround01_l	%f52, %f10, %f6, %f4
	retl
	aes_eround23_l	%f54, %f10, %f6, %f6
.type	_aes128_encrypt_2x,#function
.size	_aes128_encrypt_2x,.-_aes128_encrypt_2x

.align	32
_aes128_decrypt_1x:
___
for ($i=0; $i<4; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_dround01	%f48, %f0, %f2, %f4
	aes_dround23	%f50, %f0, %f2, %f2
	aes_dround01_l	%f52, %f4, %f2, %f0
	retl
	aes_dround23_l	%f54, %f4, %f2, %f2
.type	_aes128_decrypt_1x,#function
.size	_aes128_decrypt_1x,.-_aes128_decrypt_1x

.align	32
_aes128_decrypt_2x:
___
for ($i=0; $i<4; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_dround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_dround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_dround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_dround01	%f48, %f0, %f2, %f8
	aes_dround23	%f50, %f0, %f2, %f2
	aes_dround01	%f48, %f4, %f6, %f10
	aes_dround23	%f50, %f4, %f6, %f6
	aes_dround01_l	%f52, %f8, %f2, %f0
	aes_dround23_l	%f54, %f8, %f2, %f2
	aes_dround01_l	%f52, %f10, %f6, %f4
	retl
	aes_dround23_l	%f54, %f10, %f6, %f6
.type	_aes128_decrypt_2x,#function
.size	_aes128_decrypt_2x,.-_aes128_decrypt_2x

.align	32
_aes192_loadkey:
_aes256_loadkey:
	ldx		[$key + 0], %g4
	ldx		[$key + 8], %g5
___
for ($i=2; $i<26;$i++) {			# load key schedule
    $code.=<<___;
	ldd		[$key + `8*$i`], %f`12+2*$i`
___
}
$code.=<<___;
	retl
	nop
.type	_aes192_loadkey,#function
.size	_aes192_loadkey,.-_aes192_loadkey

.align	32
_aes192_encrypt_1x:
___
for ($i=0; $i<5; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_eround01	%f56, %f0, %f2, %f4
	aes_eround23	%f58, %f0, %f2, %f2
	aes_eround01_l	%f60, %f4, %f2, %f0
	retl
	aes_eround23_l	%f62, %f4, %f2, %f2
.type	_aes192_encrypt_1x,#function
.size	_aes192_encrypt_1x,.-_aes192_encrypt_1x

.align	32
_aes192_encrypt_2x:
___
for ($i=0; $i<5; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_eround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_eround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_eround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_eround01	%f56, %f0, %f2, %f8
	aes_eround23	%f58, %f0, %f2, %f2
	aes_eround01	%f56, %f4, %f6, %f10
	aes_eround23	%f58, %f4, %f6, %f6
	aes_eround01_l	%f60, %f8, %f2, %f0
	aes_eround23_l	%f62, %f8, %f2, %f2
	aes_eround01_l	%f60, %f10, %f6, %f4
	retl
	aes_eround23_l	%f62, %f10, %f6, %f6
.type	_aes192_encrypt_2x,#function
.size	_aes192_encrypt_2x,.-_aes192_encrypt_2x

.align	32
_aes192_decrypt_1x:
___
for ($i=0; $i<5; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_dround01	%f56, %f0, %f2, %f4
	aes_dround23	%f58, %f0, %f2, %f2
	aes_dround01_l	%f60, %f4, %f2, %f0
	retl
	aes_dround23_l	%f62, %f4, %f2, %f2
.type	_aes192_decrypt_1x,#function
.size	_aes192_decrypt_1x,.-_aes192_decrypt_1x

.align	32
_aes192_decrypt_2x:
___
for ($i=0; $i<5; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_dround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_dround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_dround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_dround01	%f56, %f0, %f2, %f8
	aes_dround23	%f58, %f0, %f2, %f2
	aes_dround01	%f56, %f4, %f6, %f10
	aes_dround23	%f58, %f4, %f6, %f6
	aes_dround01_l	%f60, %f8, %f2, %f0
	aes_dround23_l	%f62, %f8, %f2, %f2
	aes_dround01_l	%f60, %f10, %f6, %f4
	retl
	aes_dround23_l	%f62, %f10, %f6, %f6
.type	_aes192_decrypt_2x,#function
.size	_aes192_decrypt_2x,.-_aes192_decrypt_2x

.align	32
_aes256_encrypt_1x:
	aes_eround01	%f16, %f0, %f2, %f4
	aes_eround23	%f18, %f0, %f2, %f2
	ldd		[$key + 208], %f16
	ldd		[$key + 216], %f18
	aes_eround01	%f20, %f4, %f2, %f0
	aes_eround23	%f22, %f4, %f2, %f2
	ldd		[$key + 224], %f20
	ldd		[$key + 232], %f22
___
for ($i=1; $i<6; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_eround01	%f16, %f0, %f2, %f4
	aes_eround23	%f18, %f0, %f2, %f2
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	aes_eround01_l	%f20, %f4, %f2, %f0
	aes_eround23_l	%f22, %f4, %f2, %f2
	ldd		[$key + 32], %f20
	retl
	ldd		[$key + 40], %f22
.type	_aes256_encrypt_1x,#function
.size	_aes256_encrypt_1x,.-_aes256_encrypt_1x

.align	32
_aes256_encrypt_2x:
	aes_eround01	%f16, %f0, %f2, %f8
	aes_eround23	%f18, %f0, %f2, %f2
	aes_eround01	%f16, %f4, %f6, %f10
	aes_eround23	%f18, %f4, %f6, %f6
	ldd		[$key + 208], %f16
	ldd		[$key + 216], %f18
	aes_eround01	%f20, %f8, %f2, %f0
	aes_eround23	%f22, %f8, %f2, %f2
	aes_eround01	%f20, %f10, %f6, %f4
	aes_eround23	%f22, %f10, %f6, %f6
	ldd		[$key + 224], %f20
	ldd		[$key + 232], %f22
___
for ($i=1; $i<6; $i++) {
    $code.=<<___;
	aes_eround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_eround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_eround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_eround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_eround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_eround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_eround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_eround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_eround01	%f16, %f0, %f2, %f8
	aes_eround23	%f18, %f0, %f2, %f2
	aes_eround01	%f16, %f4, %f6, %f10
	aes_eround23	%f18, %f4, %f6, %f6
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	aes_eround01_l	%f20, %f8, %f2, %f0
	aes_eround23_l	%f22, %f8, %f2, %f2
	aes_eround01_l	%f20, %f10, %f6, %f4
	aes_eround23_l	%f22, %f10, %f6, %f6
	ldd		[$key + 32], %f20
	retl
	ldd		[$key + 40], %f22
.type	_aes256_encrypt_2x,#function
.size	_aes256_encrypt_2x,.-_aes256_encrypt_2x

.align	32
_aes256_decrypt_1x:
	aes_dround01	%f16, %f0, %f2, %f4
	aes_dround23	%f18, %f0, %f2, %f2
	ldd		[$key + 208], %f16
	ldd		[$key + 216], %f18
	aes_dround01	%f20, %f4, %f2, %f0
	aes_dround23	%f22, %f4, %f2, %f2
	ldd		[$key + 224], %f20
	ldd		[$key + 232], %f22
___
for ($i=1; $i<6; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f4
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f4, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f4, %f2, %f2
___
}
$code.=<<___;
	aes_dround01	%f16, %f0, %f2, %f4
	aes_dround23	%f18, %f0, %f2, %f2
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	aes_dround01_l	%f20, %f4, %f2, %f0
	aes_dround23_l	%f22, %f4, %f2, %f2
	ldd		[$key + 32], %f20
	retl
	ldd		[$key + 40], %f22
.type	_aes256_decrypt_1x,#function
.size	_aes256_decrypt_1x,.-_aes256_decrypt_1x

.align	32
_aes256_decrypt_2x:
	aes_dround01	%f16, %f0, %f2, %f8
	aes_dround23	%f18, %f0, %f2, %f2
	aes_dround01	%f16, %f4, %f6, %f10
	aes_dround23	%f18, %f4, %f6, %f6
	ldd		[$key + 208], %f16
	ldd		[$key + 216], %f18
	aes_dround01	%f20, %f8, %f2, %f0
	aes_dround23	%f22, %f8, %f2, %f2
	aes_dround01	%f20, %f10, %f6, %f4
	aes_dround23	%f22, %f10, %f6, %f6
	ldd		[$key + 224], %f20
	ldd		[$key + 232], %f22
___
for ($i=1; $i<6; $i++) {
    $code.=<<___;
	aes_dround01	%f`16+8*$i+0`, %f0, %f2, %f8
	aes_dround23	%f`16+8*$i+2`, %f0, %f2, %f2
	aes_dround01	%f`16+8*$i+0`, %f4, %f6, %f10
	aes_dround23	%f`16+8*$i+2`, %f4, %f6, %f6
	aes_dround01	%f`16+8*$i+4`, %f8, %f2, %f0
	aes_dround23	%f`16+8*$i+6`, %f8, %f2, %f2
	aes_dround01	%f`16+8*$i+4`, %f10, %f6, %f4
	aes_dround23	%f`16+8*$i+6`, %f10, %f6, %f6
___
}
$code.=<<___;
	aes_dround01	%f16, %f0, %f2, %f8
	aes_dround23	%f18, %f0, %f2, %f2
	aes_dround01	%f16, %f4, %f6, %f10
	aes_dround23	%f18, %f4, %f6, %f6
	ldd		[$key + 16], %f16
	ldd		[$key + 24], %f18
	aes_dround01_l	%f20, %f8, %f2, %f0
	aes_dround23_l	%f22, %f8, %f2, %f2
	aes_dround01_l	%f20, %f10, %f6, %f4
	aes_dround23_l	%f22, %f10, %f6, %f6
	ldd		[$key + 32], %f20
	retl
	ldd		[$key + 40], %f22
.type	_aes256_decrypt_2x,#function
.size	_aes256_decrypt_2x,.-_aes256_decrypt_2x
___

sub aes_cbc_encrypt_implement {
my $bits = shift;

$code.=<<___;
.globl	aes${bits}_t4_cbc_encrypt
.align	32
aes${bits}_t4_cbc_encrypt:
	save		%sp, -$frame, %sp
___
$code.=<<___ if (!$evp);
	andcc		$ivec, 7, $ivoff
	alignaddr	$ivec, %g0, $ivec

	ldd		[$ivec + 0], %f0	! load ivec
	bz,pt		%icc, 1f
	ldd		[$ivec + 8], %f2
	ldd		[$ivec + 16], %f4
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
1:
___
$code.=<<___ if ($evp);
	ld		[$ivec + 0], %f0
	ld		[$ivec + 4], %f1
	ld		[$ivec + 8], %f2
	ld		[$ivec + 12], %f3
___
$code.=<<___;
	call		_aes${bits}_loadkey
	srlx		$len, 4, $len
	and		$inp, 7, $ileft
	andn		$inp, 7, $inp
	sll		$ileft, 3, $ileft
	mov		64, $iright
	mov		0xff, $omask
	sub		$iright, $ileft, $iright
	and		$out, 7, $ooff
	alignaddrl	$out, %g0, $out
	srl		$omask, $ooff, $omask

.L${bits}_cbc_enc_loop:
	ldx		[$inp + 0], %o0
	brz,pt		$ileft, 4f
	ldx		[$inp + 8], %o1

	ldx		[$inp + 16], %o2
	sllx		%o0, $ileft, %o0
	srlx		%o1, $iright, %g1
	sllx		%o1, $ileft, %o1
	or		%g1, %o0, %o0
	srlx		%o2, $iright, %o2
	or		%o2, %o1, %o1
4:
	xor		%g4, %o0, %o0		! ^= rk[0]
	xor		%g5, %o1, %o1
	movxtod		%o0, %f12
	movxtod		%o1, %f14

	fxor		%f12, %f0, %f0		! ^= ivec
	fxor		%f14, %f2, %f2
	call		_aes${bits}_encrypt_1x
	add		$inp, 16, $inp

	brnz,pn		$ooff, 2f
	sub		$len, 1, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	brnz,pt		$len, .L${bits}_cbc_enc_loop
	add		$out, 16, $out
___
$code.=<<___ if ($evp);
	st		%f0, [$ivec + 0]
	st		%f1, [$ivec + 4]
	st		%f2, [$ivec + 8]
	st		%f3, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, 3f
	nop

	std		%f0, [$ivec + 0]	! write out ivec
	std		%f2, [$ivec + 8]
___
$code.=<<___;
	ret
	restore

.align	16
2:	ldxa		[$inp]0x82, %o0		! avoid read-after-write hazard
						! and ~3x deterioration
						! in inp==out case
	faligndata	%f0, %f0, %f4		! handle unaligned output
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $omask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $omask, $omask
	stda		%f8, [$out + $omask]0xc0	! partial store

	brnz,pt		$len, .L${bits}_cbc_enc_loop+4
	orn		%g0, $omask, $omask
___
$code.=<<___ if ($evp);
	st		%f0, [$ivec + 0]
	st		%f1, [$ivec + 4]
	st		%f2, [$ivec + 8]
	st		%f3, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, 3f
	nop

	std		%f0, [$ivec + 0]	! write out ivec
	std		%f2, [$ivec + 8]
	ret
	restore

.align	16
3:	alignaddrl	$ivec, $ivoff, %g0	! handle unaligned ivec
	mov		0xff, $omask
	srl		$omask, $ivoff, $omask
	faligndata	%f0, %f0, %f4
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8
	stda		%f4, [$ivec + $omask]0xc0
	std		%f6, [$ivec + 8]
	add		$ivec, 16, $ivec
	orn		%g0, $omask, $omask
	stda		%f8, [$ivec + $omask]0xc0
___
$code.=<<___;
	ret
	restore
.type	aes${bits}_t4_cbc_encrypt,#function
.size	aes${bits}_t4_cbc_encrypt,.-aes${bits}_t4_cbc_encrypt
___
}

&aes_cbc_encrypt_implement(128);
&aes_cbc_encrypt_implement(192);
&aes_cbc_encrypt_implement(256);

sub aes_cbc_decrypt_implement {
my $bits = shift;

$code.=<<___;
.globl	aes${bits}_t4_cbc_decrypt
.align	32
aes${bits}_t4_cbc_decrypt:
	save		%sp, -$frame, %sp
___
$code.=<<___ if (!$evp);
	andcc		$ivec, 7, $ivoff
	alignaddr	$ivec, %g0, $ivec

	ldd		[$ivec + 0], %f12	! load ivec
	bz,pt		%icc, 1f
	ldd		[$ivec + 8], %f14
	ldd		[$ivec + 16], %f0
	faligndata	%f12, %f14, %f12
	faligndata	%f14, %f0, %f14
1:
___
$code.=<<___ if ($evp);
	ld		[$ivec + 0], %f12	! load ivec
	ld		[$ivec + 4], %f13
	ld		[$ivec + 8], %f14
	ld		[$ivec + 12], %f15
___
$code.=<<___;
	call		_aes${bits}_loadkey
	srlx		$len, 4, $len
	andcc		$len, 1, %g0		! is number of blocks even?
	and		$inp, 7, $ileft
	andn		$inp, 7, $inp
	sll		$ileft, 3, $ileft
	mov		64, $iright
	mov		0xff, $omask
	sub		$iright, $ileft, $iright
	and		$out, 7, $ooff
	alignaddrl	$out, %g0, $out
	bz		%icc, .L${bits}_cbc_dec_loop2x
	srl		$omask, $ooff, $omask
.L${bits}_cbc_dec_loop:
	ldx		[$inp + 0], %o0
	brz,pt		$ileft, 4f
	ldx		[$inp + 8], %o1

	ldx		[$inp + 16], %o2
	sllx		%o0, $ileft, %o0
	srlx		%o1, $iright, %g1
	sllx		%o1, $ileft, %o1
	or		%g1, %o0, %o0
	srlx		%o2, $iright, %o2
	or		%o2, %o1, %o1
4:
	xor		%g4, %o0, %o2		! ^= rk[0]
	xor		%g5, %o1, %o3
	movxtod		%o2, %f0
	movxtod		%o3, %f2

	call		_aes${bits}_decrypt_1x
	add		$inp, 16, $inp

	fxor		%f12, %f0, %f0		! ^= ivec
	fxor		%f14, %f2, %f2
	movxtod		%o0, %f12
	movxtod		%o1, %f14

	brnz,pn		$ooff, 2f
	sub		$len, 1, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	brnz,pt		$len, .L${bits}_cbc_dec_loop2x
	add		$out, 16, $out
___
$code.=<<___ if ($evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$code.=<<___;
	ret
	restore

.align	16
2:	ldxa		[$inp]0x82, %o0		! avoid read-after-write hazard
						! and ~3x deterioration
						! in inp==out case
	faligndata	%f0, %f0, %f4		! handle unaligned output
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $omask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $omask, $omask
	stda		%f8, [$out + $omask]0xc0	! partial store

	brnz,pt		$len, .L${bits}_cbc_dec_loop2x+4
	orn		%g0, $omask, $omask
___
$code.=<<___ if ($evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$code.=<<___;
	ret
	restore

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
.align	32
.L${bits}_cbc_dec_loop2x:
	ldx		[$inp + 0], %o0
	ldx		[$inp + 8], %o1
	ldx		[$inp + 16], %o2
	brz,pt		$ileft, 4f
	ldx		[$inp + 24], %o3

	ldx		[$inp + 32], %o4
	sllx		%o0, $ileft, %o0
	srlx		%o1, $iright, %g1
	or		%g1, %o0, %o0
	sllx		%o1, $ileft, %o1
	srlx		%o2, $iright, %g1
	or		%g1, %o1, %o1
	sllx		%o2, $ileft, %o2
	srlx		%o3, $iright, %g1
	or		%g1, %o2, %o2
	sllx		%o3, $ileft, %o3
	srlx		%o4, $iright, %o4
	or		%o4, %o3, %o3
4:
	xor		%g4, %o0, %o4		! ^= rk[0]
	xor		%g5, %o1, %o5
	movxtod		%o4, %f0
	movxtod		%o5, %f2
	xor		%g4, %o2, %o4
	xor		%g5, %o3, %o5
	movxtod		%o4, %f4
	movxtod		%o5, %f6

	call		_aes${bits}_decrypt_2x
	add		$inp, 32, $inp

	movxtod		%o0, %f8
	movxtod		%o1, %f10
	fxor		%f12, %f0, %f0		! ^= ivec
	fxor		%f14, %f2, %f2
	movxtod		%o2, %f12
	movxtod		%o3, %f14
	fxor		%f8, %f4, %f4
	fxor		%f10, %f6, %f6

	brnz,pn		$ooff, 2f
	sub		$len, 2, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	std		%f4, [$out + 16]
	std		%f6, [$out + 24]
	brnz,pt		$len, .L${bits}_cbc_dec_loop2x
	add		$out, 32, $out
___
$code.=<<___ if ($evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$code.=<<___;
	ret
	restore

.align	16
2:	ldxa		[$inp]0x82, %o0		! avoid read-after-write hazard
						! and ~3x deterioration
						! in inp==out case
	faligndata	%f0, %f0, %f8		! handle unaligned output
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4
	faligndata	%f6, %f6, %f6
	stda		%f8, [$out + $omask]0xc0	! partial store
	std		%f0, [$out + 8]
	std		%f2, [$out + 16]
	std		%f4, [$out + 24]
	add		$out, 32, $out
	orn		%g0, $omask, $omask
	stda		%f6, [$out + $omask]0xc0	! partial store

	brnz,pt		$len, .L${bits}_cbc_dec_loop2x+4
	orn		%g0, $omask, $omask
___
$code.=<<___ if ($evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$code.=<<___ if (!$evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
	ret
	restore

.align	16
.L${bits}_cbc_dec_unaligned_ivec:
	alignaddrl	$ivec, $ivoff, %g0	! handle unaligned ivec
	mov		0xff, $omask
	srl		$omask, $ivoff, $omask
	faligndata	%f12, %f12, %f0
	faligndata	%f12, %f14, %f2
	faligndata	%f14, %f14, %f4
	stda		%f0, [$ivec + $omask]0xc0
	std		%f2, [$ivec + 8]
	add		$ivec, 16, $ivec
	orn		%g0, $omask, $omask
	stda		%f4, [$ivec + $omask]0xc0
___
$code.=<<___;
	ret
	restore
.type	aes${bits}_t4_cbc_decrypt,#function
.size	aes${bits}_t4_cbc_decrypt,.-aes${bits}_t4_cbc_decrypt
___
}

&aes_cbc_decrypt_implement(128);
&aes_cbc_decrypt_implement(192);
&aes_cbc_decrypt_implement(256);

sub aes_ctr32_implement {
my $bits = shift;

$code.=<<___;
.globl	aes${bits}_t4_ctr32_encrypt
.align	32
aes${bits}_t4_ctr32_encrypt:
	save		%sp, -$frame, %sp

	call		_aes${bits}_loadkey
	nop

	ld		[$ivec + 0], %l4	! counter
	ld		[$ivec + 4], %l5
	ld		[$ivec + 8], %l6
	ld		[$ivec + 12], %l7

	sllx		%l4, 32, %o5
	or		%l5, %o5, %o5
	sllx		%l6, 32, %g1
	xor		%o5, %g4, %g4		! ^= rk[0]
	xor		%g1, %g5, %g5
	movxtod		%g4, %f14		! most significant 64 bits

	andcc		$len, 1, %g0		! is number of blocks even?
	and		$inp, 7, $ileft
	andn		$inp, 7, $inp
	sll		$ileft, 3, $ileft
	mov		64, $iright
	mov		0xff, $omask
	sub		$iright, $ileft, $iright
	and		$out, 7, $ooff
	alignaddrl	$out, %g0, $out
	bz		%icc, .L${bits}_ctr32_loop2x
	srl		$omask, $ooff, $omask
.L${bits}_ctr32_loop:
	ldx		[$inp + 0], %o0
	brz,pt		$ileft, 4f
	ldx		[$inp + 8], %o1

	ldx		[$inp + 16], %o2
	sllx		%o0, $ileft, %o0
	srlx		%o1, $iright, %g1
	sllx		%o1, $ileft, %o1
	or		%g1, %o0, %o0
	srlx		%o2, $iright, %o2
	or		%o2, %o1, %o1
4:
	xor		%g5, %l7, %g1		! ^= rk[0]
	add		%l7, 1, %l7
	movxtod		%g1, %f2
	srl		%l7, 0, %l7		! clruw

	aes_eround01	%f16, %f14, %f2, %f4
	aes_eround23	%f18, %f14, %f2, %f2
	call		_aes${bits}_encrypt_1x+8
	add		$inp, 16, $inp

	movxtod		%o0, %f10
	movxtod		%o1, %f12
	fxor		%f10, %f0, %f0		! ^= inp
	fxor		%f12, %f2, %f2

	brnz,pn		$ooff, 2f
	sub		$len, 1, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	brnz,pt		$len, .L${bits}_ctr32_loop2x
	add		$out, 16, $out

	ret
	restore

.align	16
2:	ldxa		[$inp]0x82, %o0		! avoid read-after-write hazard
						! and ~3x deterioration
						! in inp==out case
	faligndata	%f0, %f0, %f4		! handle unaligned output
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8
	stda		%f4, [$out + $omask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $omask, $omask
	stda		%f8, [$out + $omask]0xc0	! partial store

	brnz,pt		$len, .L${bits}_ctr32_loop2x+4
	orn		%g0, $omask, $omask

	ret
	restore

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
.align	32
.L${bits}_ctr32_loop2x:
	ldx		[$inp + 0], %o0
	ldx		[$inp + 8], %o1
	ldx		[$inp + 16], %o2
	brz,pt		$ileft, 4f
	ldx		[$inp + 24], %o3

	ldx		[$inp + 32], %o4
	sllx		%o0, $ileft, %o0
	srlx		%o1, $iright, %g1
	or		%g1, %o0, %o0
	sllx		%o1, $ileft, %o1
	srlx		%o2, $iright, %g1
	or		%g1, %o1, %o1
	sllx		%o2, $ileft, %o2
	srlx		%o3, $iright, %g1
	or		%g1, %o2, %o2
	sllx		%o3, $ileft, %o3
	srlx		%o4, $iright, %o4
	or		%o4, %o3, %o3
4:
	xor		%g5, %l7, %g1		! ^= rk[0]
	add		%l7, 1, %l7
	movxtod		%g1, %f2
	srl		%l7, 0, %l7		! clruw
	xor		%g5, %l7, %g1
	add		%l7, 1, %l7
	movxtod		%g1, %f6
	srl		%l7, 0, %l7		! clruw

	aes_eround01	%f16, %f14, %f2, %f8
	aes_eround23	%f18, %f14, %f2, %f2
	aes_eround01	%f16, %f14, %f6, %f10
	aes_eround23	%f18, %f14, %f6, %f6
	call		_aes${bits}_encrypt_2x+16
	add		$inp, 32, $inp

	movxtod		%o0, %f8
	movxtod		%o1, %f10
	movxtod		%o2, %f12
	fxor		%f8, %f0, %f0		! ^= inp
	movxtod		%o3, %f8
	fxor		%f10, %f2, %f2
	fxor		%f12, %f4, %f4
	fxor		%f8, %f6, %f6

	brnz,pn		$ooff, 2f
	sub		$len, 2, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	std		%f4, [$out + 16]
	std		%f6, [$out + 24]
	brnz,pt		$len, .L${bits}_ctr32_loop2x
	add		$out, 32, $out

	ret
	restore

.align	16
2:	ldxa		[$inp]0x82, %o0		! avoid read-after-write hazard
						! and ~3x deterioration
						! in inp==out case
	faligndata	%f0, %f0, %f8		! handle unaligned output
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4
	faligndata	%f6, %f6, %f6

	stda		%f8, [$out + $omask]0xc0	! partial store
	std		%f0, [$out + 8]
	std		%f2, [$out + 16]
	std		%f4, [$out + 24]
	add		$out, 32, $out
	orn		%g0, $omask, $omask
	stda		%f6, [$out + $omask]0xc0	! partial store

	brnz,pt		$len, .L${bits}_ctr32_loop2x+4
	orn		%g0, $omask, $omask

	ret
	restore
.type	aes${bits}_t4_ctr32_encrypt,#function
.size	aes${bits}_t4_ctr32_encrypt,.-aes${bits}_t4_ctr32_encrypt
___
}

if ($evp) {
    &aes_ctr32_implement(128);
    &aes_ctr32_implement(192);
    &aes_ctr32_implement(256);
}
}}}

if (!$evp) {
$code.=<<___;
.global	AES_encrypt
AES_encrypt=aes_t4_encrypt
.global	AES_decrypt
AES_decrypt=aes_t4_decrypt
.global	AES_set_encrypt_key
AES_set_encrypt_key=aes_t4_set_encrypt_key
.global	AES_set_decrypt_key
AES_set_decrypt_key=aes_t4_set_decrypt_key
___

my ($inp,$out,$len,$key,$ivec,$enc)=map("%o$_",(0..5));

$code.=<<___;
.globl	AES_cbc_encrypt
.align	32
AES_cbc_encrypt:
	ld		[$key + 240], %g1
	nop
	brz		$enc, .Lcbc_decrypt
	cmp		%g1, 12

	bl,pt		%icc, aes128_t4_cbc_encrypt
	nop
	be,pn		%icc, aes192_t4_cbc_encrypt
	nop
	ba		aes256_t4_cbc_encrypt
	nop

.Lcbc_decrypt:
	bl,pt		%icc, aes128_t4_cbc_decrypt
	nop
	be,pn		%icc, aes192_t4_cbc_decrypt
	nop
	ba		aes256_t4_cbc_decrypt
	nop
.type	AES_cbc_encrypt,#function
.size	AES_cbc_encrypt,.-AES_cbc_encrypt
___
}
$code.=<<___;
.asciz	"AES for SPARC T4, David S. Miller, Andy Polyakov"
.align	4
___
# Purpose of these subroutines is to explicitly encode VIS instructions,
# so that one can compile the module without having to specify VIS
# extentions on compiler command line, e.g. -xarch=v9 vs. -xarch=v9a.
# Idea is to reserve for option to produce "universal" binary and let
# programmer detect if current CPU is VIS capable at run-time.
sub unvis {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %visopf = (	"faligndata"	=> 0x048,
		"fxor"		=> 0x06c	);

    $ref = "$mnemonic\t$rs1,$rs2,$rd";

    if ($opf=$visopf{$mnemonic}) {
	foreach ($rs1,$rs2,$rd) {
	    return $ref if (!/%f([0-9]{1,2})/);
	    $_=$1;
	    if ($1>=32) {
		return $ref if ($1&1);
		# re-encode for upper double register addressing
		$_=($1|$1>>5)&31;
	    }
	}

	return	sprintf ".word\t0x%08x !%s",
			0x81b00000|$rd<<25|$rs1<<14|$opf<<5|$rs2,
			$ref;
    } else {
	return $ref;
    }
}
sub unalignaddr {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my %bias = ( "g" => 0, "o" => 8, "l" => 16, "i" => 24 );
my $ref = "$mnemonic\t$rs1,$rs2,$rd";
my $opf = $mnemonic =~ /l$/ ? 0x01a :0x18;

    foreach ($rs1,$rs2,$rd) {
	if (/%([goli])([0-7])/)	{ $_=$bias{$1}+$2; }
	else			{ return $ref; }
    }
    return  sprintf ".word\t0x%08x !%s",
		    0x81b00000|$rd<<25|$rs1<<14|$opf<<5|$rs2,
		    $ref;
}

sub unaes_round {	# 4-argument instructions
my ($mnemonic,$rs1,$rs2,$rs3,$rd)=@_;
my ($ref,$opf);
my %aesopf = (	"aes_eround01"	=> 0,
		"aes_eround23"	=> 1,
		"aes_dround01"	=> 2,
		"aes_dround23"	=> 3,
		"aes_eround01_l"=> 4,
		"aes_eround23_l"=> 5,
		"aes_dround01_l"=> 6,
		"aes_dround23_l"=> 7,
		"aes_kexpand1"	=> 8	);

    $ref = "$mnemonic\t$rs1,$rs2,$rs3,$rd";

    if (defined($opf=$aesopf{$mnemonic})) {
	$rs3 = ($rs3 =~ /%f([0-6]*[02468])/) ? (($1|$1>>5)&31) : $rs3;
	foreach ($rs1,$rs2,$rd) {
	    return $ref if (!/%f([0-9]{1,2})/);
	    $_=$1;
	    if ($1>=32) {
		return $ref if ($1&1);
		# re-encode for upper double register addressing
		$_=($1|$1>>5)&31;
	    }
	}

	return	sprintf ".word\t0x%08x !%s",
			2<<30|$rd<<25|0x19<<19|$rs1<<14|$rs3<<9|$opf<<5|$rs2,
			$ref;
    } else {
	return $ref;
    }
}

sub unaes_kexpand {	# 3-argument instructions
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %aesopf = (	"aes_kexpand0"	=> 0x130,
		"aes_kexpand2"	=> 0x131	);

    $ref = "$mnemonic\t$rs1,$rs2,$rd";

    if (defined($opf=$aesopf{$mnemonic})) {
	foreach ($rs1,$rs2,$rd) {
	    return $ref if (!/%f([0-9]{1,2})/);
	    $_=$1;
	    if ($1>=32) {
		return $ref if ($1&1);
		# re-encode for upper double register addressing
		$_=($1|$1>>5)&31;
	    }
	}

	return	sprintf ".word\t0x%08x !%s",
			2<<30|$rd<<25|0x36<<19|$rs1<<14|$opf<<5|$rs2,
			$ref;
    } else {
	return $ref;
    }
}

sub unmovxtox {		# 2-argument instructions
my ($mnemonic,$rs,$rd)=@_;
my %bias = ( "g" => 0, "o" => 8, "l" => 16, "i" => 24, "f" => 0 );
my ($ref,$opf);
my %movxopf = (	"movdtox"	=> 0x110,
		"movstouw"	=> 0x111,
		"movstosw"	=> 0x113,
		"movxtod"	=> 0x118,
		"movwtos"	=> 0x119	);

    $ref = "$mnemonic\t$rs,$rd";

    if (defined($opf=$movxopf{$mnemonic})) {
	foreach ($rs,$rd) {
	    return $ref if (!/%([fgoli])([0-9]{1,2})/);
	    $_=$bias{$1}+$2;
	    if ($2>=32) {
		return $ref if ($2&1);
		# re-encode for upper double register addressing
		$_=($2|$2>>5)&31;
	    }
	}

	return	sprintf ".word\t0x%08x !%s",
			2<<30|$rd<<25|0x36<<19|$opf<<5|$rs,
			$ref;
    } else {
	return $ref;
    }
}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	s/\b(aes_[edk][^\s]*)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*([%fx0-9]+),\s*(%f[0-9]{1,2})/
		&unaes_round($1,$2,$3,$4,$5)
	 /ge or
	s/\b(aes_kexpand[02])\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})/
		&unaes_kexpand($1,$2,$3,$4)
	 /ge or
	s/\b(mov[ds]to\w+)\s+(%f[0-9]{1,2}),\s*(%[goli][0-7])/
		&unmovxtox($1,$2,$3)
	 /ge or
	s/\b(mov[xw]to[ds])\s+(%[goli][0-7]),\s*(%f[0-9]{1,2})/
		&unmovxtox($1,$2,$3)
	 /ge or
	s/\b(f[^\s]*)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})/
		&unvis($1,$2,$3,$4)
	 /ge or
	s/\b(alignaddr[l]*)\s+(%[goli][0-7]),\s*(%[goli][0-7]),\s*(%[goli][0-7])/
		&unalignaddr($1,$2,$3,$4)
	 /ge;

	print $_,"\n";
}

close STDOUT;
