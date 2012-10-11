#!/usr/bin/env perl

# Specific mode implementations for SPARC T4 modules.

my ($inp,$out,$len,$key,$ivec,$enc)=map("%i$_",(0..5));
my ($ileft,$iright,$ooff,$omask,$ivoff)=map("%l$_",(1..7));

sub alg_cbc_encrypt_implement {
my ($alg,$bits) = @_;

$::code.=<<___;
.globl	${alg}${bits}_t4_cbc_encrypt
.align	32
${alg}${bits}_t4_cbc_encrypt:
	save		%sp, -$::frame, %sp
___
$::code.=<<___ if (!$::evp);
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
$::code.=<<___ if ($::evp);
	ld		[$ivec + 0], %f0
	ld		[$ivec + 4], %f1
	ld		[$ivec + 8], %f2
	ld		[$ivec + 12], %f3
___
$::code.=<<___;
	call		_${alg}${bits}_load_enckey
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
	call		_${alg}${bits}_encrypt_1x
	add		$inp, 16, $inp

	brnz,pn		$ooff, 2f
	sub		$len, 1, $len
		
	std		%f0, [$out + 0]
	std		%f2, [$out + 8]
	brnz,pt		$len, .L${bits}_cbc_enc_loop
	add		$out, 16, $out
___
$::code.=<<___ if ($::evp);
	st		%f0, [$ivec + 0]
	st		%f1, [$ivec + 4]
	st		%f2, [$ivec + 8]
	st		%f3, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
	brnz,pn		$ivoff, 3f
	nop

	std		%f0, [$ivec + 0]	! write out ivec
	std		%f2, [$ivec + 8]
___
$::code.=<<___;
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
$::code.=<<___ if ($::evp);
	st		%f0, [$ivec + 0]
	st		%f1, [$ivec + 4]
	st		%f2, [$ivec + 8]
	st		%f3, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
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
$::code.=<<___;
	ret
	restore
.type	${alg}${bits}_t4_cbc_encrypt,#function
.size	${alg}${bits}_t4_cbc_encrypt,.-${alg}${bits}_t4_cbc_encrypt
___
}

sub alg_cbc_decrypt_implement {
my ($alg,$bits) = @_;

$::code.=<<___;
.globl	${alg}${bits}_t4_cbc_decrypt
.align	32
${alg}${bits}_t4_cbc_decrypt:
	save		%sp, -$::frame, %sp
___
$::code.=<<___ if (!$::evp);
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
$::code.=<<___ if ($::evp);
	ld		[$ivec + 0], %f12	! load ivec
	ld		[$ivec + 4], %f13
	ld		[$ivec + 8], %f14
	ld		[$ivec + 12], %f15
___
$::code.=<<___;
	call		_${alg}${bits}_load_deckey
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

	call		_${alg}${bits}_decrypt_1x
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
$::code.=<<___ if ($::evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$::code.=<<___;
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
$::code.=<<___ if ($::evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$::code.=<<___;
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

	call		_${alg}${bits}_decrypt_2x
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
$::code.=<<___ if ($::evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
	brnz,pn		$ivoff, .L${bits}_cbc_dec_unaligned_ivec
	nop

	std		%f12, [$ivec + 0]	! write out ivec
	std		%f14, [$ivec + 8]
___
$::code.=<<___;
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
$::code.=<<___ if ($::evp);
	st		%f12, [$ivec + 0]
	st		%f13, [$ivec + 4]
	st		%f14, [$ivec + 8]
	st		%f15, [$ivec + 12]
___
$::code.=<<___ if (!$::evp);
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
$::code.=<<___;
	ret
	restore
.type	${alg}${bits}_t4_cbc_decrypt,#function
.size	${alg}${bits}_t4_cbc_decrypt,.-${alg}${bits}_t4_cbc_decrypt
___
}

sub alg_ctr32_implement {
my ($alg,$bits) = @_;

$::code.=<<___;
.globl	${alg}${bits}_t4_ctr32_encrypt
.align	32
${alg}${bits}_t4_ctr32_encrypt:
	save		%sp, -$::frame, %sp

	call		_${alg}${bits}_load_enckey
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
___
$::code.=<<___ if ($alg eq "aes");
	aes_eround01	%f16, %f14, %f2, %f4
	aes_eround23	%f18, %f14, %f2, %f2
___
$::code.=<<___ if ($alg eq "cmll");
	camellia_f	%f16, %f2, %f14, %f2
	camellia_f	%f18, %f14, %f2, %f0
___
$::code.=<<___;
	call		_${alg}${bits}_encrypt_1x+8
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

___
$::code.=<<___ if ($alg eq "aes");
	aes_eround01	%f16, %f14, %f2, %f8
	aes_eround23	%f18, %f14, %f2, %f2
	aes_eround01	%f16, %f14, %f6, %f10
	aes_eround23	%f18, %f14, %f6, %f6
___
$::code.=<<___ if ($alg eq "cmll");
	camellia_f	%f16, %f2, %f14, %f2
	camellia_f	%f16, %f6, %f14, %f6
	camellia_f	%f18, %f14, %f2, %f0
	camellia_f	%f18, %f14, %f6, %f4
___
$::code.=<<___;
	call		_${alg}${bits}_encrypt_2x+16
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
.type	${alg}${bits}_t4_ctr32_encrypt,#function
.size	${alg}${bits}_t4_ctr32_encrypt,.-${alg}${bits}_t4_ctr32_encrypt
___
}

# Purpose of these subroutines is to explicitly encode VIS instructions,
# so that one can compile the module without having to specify VIS
# extentions on compiler command line, e.g. -xarch=v9 vs. -xarch=v9a.
# Idea is to reserve for option to produce "universal" binary and let
# programmer detect if current CPU is VIS capable at run-time.
sub unvis {
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %visopf = (	"faligndata"	=> 0x048,
		"fnot2"		=> 0x066,
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

sub uncamellia_f {	# 4-argument instructions
my ($mnemonic,$rs1,$rs2,$rs3,$rd)=@_;
my ($ref,$opf);

    $ref = "$mnemonic\t$rs1,$rs2,$rs3,$rd";

    if (1) {
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
			2<<30|$rd<<25|0x19<<19|$rs1<<14|$rs3<<9|0xc<<5|$rs2,
			$ref;
    } else {
	return $ref;
    }
}

sub uncamellia3 {	# 3-argument instructions
my ($mnemonic,$rs1,$rs2,$rd)=@_;
my ($ref,$opf);
my %cmllopf = (	"camellia_fl"	=> 0x13c,
		"camellia_fli"	=> 0x13d	);

    $ref = "$mnemonic\t$rs1,$rs2,$rd";

    if (defined($opf=$cmllopf{$mnemonic})) {
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

sub emit_assembler {
    foreach (split("\n",$::code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	s/\b(f[a-z]+2[sd]*)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})\s*$/$1\t%f0,$2,$3/g;

	s/\b(aes_[edk][^\s]*)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*([%fx0-9]+),\s*(%f[0-9]{1,2})/
		&unaes_round($1,$2,$3,$4,$5)
	 /ge or
	s/\b(aes_kexpand[02])\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})/
		&unaes_kexpand($1,$2,$3,$4)
	 /ge or
	s/\b(camellia_f)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*([%fx0-9]+),\s*(%f[0-9]{1,2})/
		&uncamellia_f($1,$2,$3,$4,$5)
	 /ge or
	s/\b(camellia_[^s]+)\s+(%f[0-9]{1,2}),\s*(%f[0-9]{1,2}),\s*(%f[0-9]{1,2})/
		&uncamellia3($1,$2,$3,$4)
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
}

1;
