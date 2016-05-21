#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# March 2016
#
# Initial support for Fujitsu SPARC64 X/X+ comprises minimally
# required key setup and single-block procedures.

$output = pop;
open STDOUT,">$output";

{
my ($inp,$out,$key,$rounds,$tmp,$mask) = map("%o$_",(0..5));

$code.=<<___;
.text

.globl	aes_fx_encrypt
.align	32
aes_fx_encrypt:
	and		$inp, 7, $tmp		! is input aligned?
	alignaddr	$inp, %g0, $inp
	ld		[$key + 240], $rounds
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8

	ldd		[$inp + 0], %f0		! load input
	brz,pt		$tmp, .Lenc_inp_aligned
	ldd		[$inp + 8], %f2

	ldd		[$inp + 16], %f4
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2

.Lenc_inp_aligned:
	ldd		[$key + 16], %f10
	ldd		[$key + 24], %f12
	add		$key, 32, $key

	fxor		%f0, %f6, %f0		! ^=round[0]
	fxor		%f2, %f8, %f2
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8
	sub		$rounds, 4, $rounds

.Loop_enc:
	fmovd		%f0, %f4
	faesencx	%f2, %f10, %f0
	faesencx	%f4, %f12, %f2
	ldd		[$key + 16], %f10
	ldd		[$key + 24], %f12
	add		$key, 32, $key

	fmovd		%f0, %f4
	faesencx	%f2, %f6, %f0
	faesencx	%f4, %f8, %f2
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8

	brnz,a		$rounds, .Loop_enc
	sub		$rounds, 2, $rounds

	andcc		$out, 7, $tmp		! is output aligned?
	mov		0xff, $mask
	alignaddrl	$out, %g0, $out
	srl		$mask, $tmp, $mask

	fmovd		%f0, %f4
	faesencx	%f2, %f10, %f0
	faesencx	%f4, %f12, %f2
	fmovd		%f0, %f4
	faesenclx	%f2, %f6, %f0
	faesenclx	%f4, %f8, %f2

	bnz,pn		%icc, .Lenc_out_unaligned
	nop

	std		%f0, [$out + 0]
	retl
	std		%f2, [$out + 8]

.Lenc_out_unaligned:
	faligndata	%f0, %f0, %f4
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $mask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $mask, $mask
	retl
	stda		%f8, [$out + $mask]0xc0	! partial store
.size	aes_fx_encrypt,.-aes_fx_encrypt

.globl	aes_fx_decrypt
.align	32
aes_fx_decrypt:
	and		$inp, 7, $tmp		! is input aligned?
	alignaddr	$inp, %g0, $inp
	ld		[$key + 240], $rounds
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8

	ldd		[$inp + 0], %f0		! load input
	brz,pt		$tmp, .Ldec_inp_aligned
	ldd		[$inp + 8], %f2

	ldd		[$inp + 16], %f4
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2

.Ldec_inp_aligned:
	ldd		[$key + 16], %f10
	ldd		[$key + 24], %f12
	add		$key, 32, $key

	fxor		%f0, %f6, %f0		! ^=round[0]
	fxor		%f2, %f8, %f2
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8
	sub		$rounds, 4, $rounds

.Loop_dec:
	fmovd		%f0, %f4
	faesdecx	%f2, %f10, %f0
	faesdecx	%f4, %f12, %f2
	ldd		[$key + 16], %f10
	ldd		[$key + 24], %f12
	add		$key, 32, $key

	fmovd		%f0, %f4
	faesdecx	%f2, %f6, %f0
	faesdecx	%f4, %f8, %f2
	ldd		[$key +  0], %f6
	ldd		[$key +  8], %f8

	brnz,a		$rounds, .Loop_dec
	sub		$rounds, 2, $rounds

	andcc		$out, 7, $tmp		! is output aligned?
	mov		0xff, $mask
	alignaddrl	$out, %g0, $out
	srl		$mask, $tmp, $mask

	fmovd		%f0, %f4
	faesdecx	%f2, %f10, %f0
	faesdecx	%f4, %f12, %f2
	fmovd		%f0, %f4
	faesdeclx	%f2, %f6, %f0
	faesdeclx	%f4, %f8, %f2

	bnz,pn		%icc, .Ldec_out_unaligned
	nop

	std		%f0, [$out + 0]
	retl
	std		%f2, [$out + 8]

.Ldec_out_unaligned:
	faligndata	%f0, %f0, %f4
	faligndata	%f0, %f2, %f6
	faligndata	%f2, %f2, %f8

	stda		%f4, [$out + $mask]0xc0	! partial store
	std		%f6, [$out + 8]
	add		$out, 16, $out
	orn		%g0, $mask, $mask
	retl
	stda		%f8, [$out + $mask]0xc0	! partial store
.size	aes_fx_decrypt,.-aes_fx_decrypt
___
}
{
my ($inp,$bits,$out,$tmp,$inc) = map("%o$_",(0..5));
$code.=<<___;
.globl	aes_fx_set_decrypt_key
.align	32
aes_fx_set_decrypt_key:
	b		.Lset_encrypt_key
	mov		-1, $inc
	retl
	nop
.size	aes_fx_set_decrypt_key,.-aes_fx_set_decrypt_key

.globl	aes_fx_set_encrypt_key
.align	32
aes_fx_set_encrypt_key:
	mov		1, $inc
.Lset_encrypt_key:
	and		$inp, 7, $tmp
	alignaddr	$inp, %g0, $inp
	nop

	cmp		$bits, 192
	ldd		[$inp + 0], %f0
	bl,pt		%icc, .L128
	ldd		[$inp + 8], %f2

	be,pt		%icc, .L192
	ldd		[$inp + 16], %f4
	brz,pt		$tmp, .L256aligned
	ldd		[$inp + 24], %f6

	ldd		[$inp + 32], %f8
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4
	faligndata	%f6, %f8, %f6

.L256aligned:
	mov		14, $bits
	and		$inc, `14*16`, $tmp
	st		$bits, [$out + 240]	! store rounds
	add		$out, $tmp, $out	! start or end of key schedule
	sllx		$inc, 4, $inc		! 16 or -16
___
for ($i=0; $i<6; $i++) {
    $code.=<<___;
	std		%f0, [$out + 0]
	faeskeyx	%f6, `0x10+$i`, %f0
	std		%f2, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f0, 0x00, %f2
	std		%f4, [$out + 0]
	faeskeyx	%f2, 0x01, %f4
	std		%f6, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f4, 0x00, %f6
___
}
$code.=<<___;
	std		%f0, [$out + 0]
	faeskeyx	%f6, `0x10+$i`, %f0
	std		%f2, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f0, 0x00, %f2
	std		%f4,[$out+0]
	std		%f6,[$out+8]
	add		$out, $inc, $out
	std		%f0,[$out+0]
	std		%f2,[$out+8]
	retl
	xor		%o0, %o0, %o0		! return 0

.align	16
.L192:
	brz,pt		$tmp, .L192aligned
	nop

	ldd		[$inp + 24], %f6
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2
	faligndata	%f4, %f6, %f4

.L192aligned:
	mov		12, $bits
	and		$inc, `12*16`, $tmp
	st		$bits, [$out + 240]	! store rounds
	add		$out, $tmp, $out	! start or end of key schedule
	sllx		$inc, 4, $inc		! 16 or -16
___
for ($i=0; $i<8; $i+=2) {
    $code.=<<___;
	std		%f0, [$out + 0]
	faeskeyx	%f4, `0x10+$i`, %f0
	std		%f2, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f0, 0x00, %f2
	std		%f4, [$out + 0]
	faeskeyx	%f2, 0x00, %f4
	std		%f0, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f4, `0x10+$i+1`, %f0
	std		%f2, [$out + 0]
	faeskeyx	%f0, 0x00, %f2
	std		%f4, [$out + 8]
	add		$out, $inc, $out
___
$code.=<<___		if ($i<6);
	faeskeyx	%f2, 0x00, %f4
___
}
$code.=<<___;
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	retl
	xor		%o0, %o0, %o0		! return 0

.align	16
.L128:
	brz,pt		$tmp, .L128aligned
	nop

	ldd		[$inp + 16], %f4
	faligndata	%f0, %f2, %f0
	faligndata	%f2, %f4, %f2

.L128aligned:
	mov		10, $bits
	and		$inc, `10*16`, $tmp
	st		$bits, [$out + 240]	! store rounds
	add		$out, $tmp, $out	! start or end of key schedule
	sllx		$inc, 4, $inc		! 16 or -16
___
for ($i=0; $i<10; $i++) {
    $code.=<<___;
	std		%f0, [$out + 0]
	faeskeyx	%f2, `0x10+$i`, %f0
	std		%f2, [$out + 8]
	add		$out, $inc, $out
	faeskeyx	%f0, 0x00, %f2
___
}
$code.=<<___;
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	retl
	xor		%o0, %o0, %o0		! return 0
.size	aes_fx_set_encrypt_key,.-aes_fx_set_encrypt_key
___
}

# Purpose of these subroutines is to explicitly encode VIS instructions,
# so that one can compile the module without having to specify VIS
# extensions on compiler command line, e.g. -xarch=v9 vs. -xarch=v9a.
# Idea is to reserve for option to produce "universal" binary and let
# programmer detect if current CPU is VIS capable at run-time.
sub unvis {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %visopf = (	"faligndata"	=> 0x048,
		"bshuffle"	=> 0x04c,
		"fxor"		=> 0x06c,
		"fsrc2"		=> 0x078	);

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

sub unvis3 {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my %bias = ( "g" => 0, "o" => 8, "l" => 16, "i" => 24 );
my ($ref,$opf);
my %visopf = (	"alignaddr"	=> 0x018,
		"bmask"		=> 0x019,
		"alignaddrl"	=> 0x01a	);

    $ref = "$mnemonic\t$rs1,$rs2,$rd";

    if ($opf=$visopf{$mnemonic}) {
	foreach ($rs1,$rs2,$rd) {
	    return $ref if (!/%([goli])([0-9])/);
	    $_=$bias{$1}+$2;
	}

	return	sprintf ".word\t0x%08x !%s",
			0x81b00000|$rd<<25|$rs1<<14|$opf<<5|$rs2,
			$ref;
    } else {
	return $ref;
    }
}

sub unfx {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %aesopf = (	"faesencx"	=> 0x90,
		"faesdecx"	=> 0x91,
		"faesenclx"	=> 0x92,
		"faesdeclx"	=> 0x93,
		"faeskeyx"	=> 0x94	);

    $ref = "$mnemonic\t$rs1,$rs2,$rd";

    if (defined($opf=$aesopf{$mnemonic})) {
	$rs2 = ($rs2 =~ /%f([0-6]*[02468])/) ? (($1|$1>>5)&31) : $rs2;
	$rs2 = oct($rs2) if ($rs2 =~ /^0/);

	foreach ($rs1,$rd) {
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

foreach (split("\n",$code)) {
    s/\`([^\`]*)\`/eval $1/ge;

    s/\b(faes[^x]{3,4}x)\s+(%f[0-9]{1,2}),\s*([%fx0-9]+),\s*(%f[0-9]{1,2})/
		&unfx($1,$2,$3,$4,$5)
     /ge or
    s/\b([fb][^\s]*)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})/
		&unvis($1,$2,$3,$4)
     /ge or
    s/\b(alignaddr[l]*)\s+(%[goli][0-7]),\s*(%[goli][0-7]),\s*(%[goli][0-7])/
		&unvis3($1,$2,$3,$4)
     /ge;
    print $_,"\n";
}

close STDOUT;
