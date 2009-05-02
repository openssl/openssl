#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements support for Intel AES-NI extension. In
# OpenSSL context it's used with Intel engine, but can also be used as
# drop-in replacement for crypto/aes/asm/aes-x86_64.pl [see below for
# details].

$PREFIX="aesni";	# if $PREFIX is set to "AES", the script
			# generates drop-in replacement for
			# crypto/aes/asm/aes-x86_64.pl:-)

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

$movkey = $PREFIX eq "aesni" ? "movaps" : "movups";
@_4args=$win64?	("%rcx","%rdx","%r8", "%r9") :	# Win64 order
		("%rdi","%rsi","%rdx","%rcx");	# Unix order

$code=".text\n";

$rounds="%eax";	# input to and changed by aesni_[en|de]cryptN !!!
# this is natural Unix argument order for public $PREFIX_[ecb|cbc]_encrypt ...
$inp="%rdi";
$out="%rsi";
$len="%rdx";
$key="%rcx";	# input to and changed by aesni_[en|de]cryptN !!!
$ivp="%r8";	# cbc

$rnds_="%r10d";	# backup copy for $rounds
$key_="%r11";	# backup copy for $key

# %xmm register layout
$inout0="%xmm0";	$inout1="%xmm1";
$inout2="%xmm2";	$inout3="%xmm3";
$rndkey0="%xmm4";	$rndkey1="%xmm5";

$iv="%xmm6";		$in0="%xmm7";	# used in CBC decrypt
$in1="%xmm8";		$in2="%xmm9";

# Inline version of internal aesni_[en|de]crypt1.
#
# Why folded loop? Because aes[enc|dec] is slow enough to accommodate
# cycles which take care of loop variables...
{ my $sn;
sub aesni_generate1 {
my ($p,$key,$rounds)=@_;
++$sn;
$code.=<<___;
	$movkey	($key),$rndkey0
	$movkey	16($key),$rndkey1
	lea	32($key),$key
	pxor	$rndkey0,$inout0
.Loop_${p}1_$sn:
	aes${p}	$rndkey1,$inout0
	dec	$rounds
	$movkey	($key),$rndkey1
	lea	16($key),$key
	jnz	.Loop_${p}1_$sn	# loop body is 16 bytes
	aes${p}last	$rndkey1,$inout0
___
}}
# void $PREFIX_[en|de]crypt (const void *inp,void *out,const AES_KEY *key);
#
{ my ($inp,$out,$key) = @_4args;

$code.=<<___;
.globl	${PREFIX}_encrypt
.type	${PREFIX}_encrypt,\@abi-omnipotent
.align	16
${PREFIX}_encrypt:
	movups	($inp),$inout0		# load input
	mov	240($key),$rounds	# pull $rounds
___
	&aesni_generate1("enc",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)		# output
	ret
.size	${PREFIX}_encrypt,.-${PREFIX}_encrypt

.globl	${PREFIX}_decrypt
.type	${PREFIX}_decrypt,\@abi-omnipotent
.align	16
${PREFIX}_decrypt:
	movups	($inp),$inout0		# load input
	mov	240($key),$rounds	# pull $rounds
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)		# output
	ret
.size	${PREFIX}_decrypt, .-${PREFIX}_decrypt
___
}

# _aesni_[en|de]crypt[34] are private interfaces, N denotes interleave
# factor. Why 3x subroutine is used in loops? Even though aes[enc|dec]
# latency is 6, it turned out that it can be scheduled only every
# *second* cycle. Thus 3x interleave is the one providing optimal
# utilization, i.e. when subroutine's throughput is virtually same as
# of non-interleaved subroutine [for number of input blocks up to 3].
# This is why it makes no sense to implement 2x subroutine. As soon
# as/if Intel improves throughput by making it possible to schedule
# the instructions in question *every* cycles I would have to
# implement 6x interleave and use it in loop...
sub aesni_generate3 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-2] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt3,\@abi-omnipotent
.align	16
_aesni_${dir}rypt3:
	$movkey	($key),$rndkey0
	shr	\$1,$rounds
	$movkey	16($key),$rndkey1
	lea	32($key),$key
	pxor	$rndkey0,$inout0
	pxor	$rndkey0,$inout1
	pxor	$rndkey0,$inout2

.L${dir}_loop3:
	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey0,$inout0
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	jnz		.L${dir}_loop3

	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	ret
.size	_aesni_${dir}rypt3,.-_aesni_${dir}rypt3
___
}
# 4x interleave is implemented to improve small block performance,
# most notably [and naturally] 4 block by ~30%. One can argue that one
# should have implemented 5x as well, but improvement would be <20%,
# so it's not worth it...
sub aesni_generate4 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-3] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt4,\@abi-omnipotent
.align	16
_aesni_${dir}rypt4:
	$movkey	($key),$rndkey0
	shr	\$1,$rounds
	$movkey	16($key),$rndkey1
	lea	32($key),$key
	pxor	$rndkey0,$inout0
	pxor	$rndkey0,$inout1
	pxor	$rndkey0,$inout2
	pxor	$rndkey0,$inout3

.L${dir}_loop4:
	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey0,$inout0
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	aes${dir}	$rndkey0,$inout3
	jnz		.L${dir}_loop4

	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	aes${dir}last	$rndkey0,$inout3
	ret
.size	_aesni_${dir}rypt4,.-_aesni_${dir}rypt4
___
}
&aesni_generate3("enc") if ($PREFIX eq "aesni");
&aesni_generate3("dec");
&aesni_generate4("enc") if ($PREFIX eq "aesni");
&aesni_generate4("dec");

if ($PREFIX eq "aesni") {
# void aesni_ecb_encrypt (const void *in, void *out,
#			  size_t length, const AES_KEY *key,
#			  int enc);
$code.=<<___;
.globl	aesni_ecb_encrypt
.type	aesni_ecb_encrypt,\@function,5
.align	16
aesni_ecb_encrypt:
	cmp	\$16,$len		# check length
	jb	.Lecb_ret

	mov	240($key),$rounds	# pull $rounds
	and	\$-16,$len
	mov	$key,$key_		# backup $key
	test	%r8d,%r8d		# 5th argument
	mov	$rounds,$rnds_		# backup $rounds
	jz	.Lecb_decrypt
#--------------------------- ECB ENCRYPT ------------------------------#
	sub	\$0x40,$len
	jbe	.Lecb_enc_tail
	jmp	.Lecb_enc_loop3
.align 16
.Lecb_enc_loop3:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	call	_aesni_encrypt3
	sub	\$0x30,$len
	lea	0x30($inp),$inp
	lea	0x30($out),$out
	movups	$inout0,-0x30($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout1,-0x20($out)
	mov	$key_,$key		# restore $key
	movups	$inout2,-0x10($out)
	ja	.Lecb_enc_loop3

.Lecb_enc_tail:
	add	\$0x40,$len
	jz	.Lecb_ret

	cmp	\$0x10,$len
	movups	($inp),$inout0
	je	.Lecb_enc_one
	cmp	\$0x20,$len
	movups	0x10($inp),$inout1
	je	.Lecb_enc_two
	cmp	\$0x30,$len
	movups	0x20($inp),$inout2
	je	.Lecb_enc_three
	movups	0x30($inp),$inout3
	call	_aesni_encrypt4
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_one:
___
	&aesni_generate1("enc",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_two:
	call	_aesni_encrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_three:
	call	_aesni_encrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	jmp	.Lecb_ret
#--------------------------- ECB DECRYPT ------------------------------#
.align	16
.Lecb_decrypt:
	sub	\$0x40,$len
	jbe	.Lecb_dec_tail
	jmp	.Lecb_dec_loop3
.align 16
.Lecb_dec_loop3:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	call	_aesni_decrypt3
	sub	\$0x30,$len
	lea	0x30($inp),$inp
	lea	0x30($out),$out
	movups	$inout0,-0x30($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout1,-0x20($out)
	mov	$key_,$key		# restore $key
	movups	$inout2,-0x10($out)
	ja	.Lecb_dec_loop3

.Lecb_dec_tail:
	add	\$0x40,$len
	jz	.Lecb_ret

	cmp	\$0x10,$len
	movups	($inp),$inout0
	je	.Lecb_dec_one
	cmp	\$0x20,$len
	movups	0x10($inp),$inout1
	je	.Lecb_dec_two
	cmp	\$0x30,$len
	movups	0x20($inp),$inout2
	je	.Lecb_dec_three
	movups	0x30($inp),$inout3
	call	_aesni_decrypt4
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_one:
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_two:
	call	_aesni_decrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_three:
	call	_aesni_decrypt3
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)

.Lecb_ret:
	ret
.size	aesni_ecb_encrypt,.-aesni_ecb_encrypt
___
}

# void $PREFIX_cbc_encrypt (const void *inp, void *out,
#			    size_t length, const AES_KEY *key,
#			    unsigned char *ivp,const int enc);
$reserved = $win64?0x40:-0x18;	# used in decrypt
$code.=<<___;
.globl	${PREFIX}_cbc_encrypt
.type	${PREFIX}_cbc_encrypt,\@function,6
.align	16
${PREFIX}_cbc_encrypt:
	test	$len,$len		# check length
	jz	.Lcbc_ret

	mov	240($key),$rnds_	# pull $rounds
	mov	$key,$key_		# backup $key
	test	%r9d,%r9d		# 6th argument
	jz	.Lcbc_decrypt
#--------------------------- CBC ENCRYPT ------------------------------#
	movups	($ivp),$inout0		# load iv as initial state
	cmp	\$16,$len
	mov	$rnds_,$rounds
	jb	.Lcbc_enc_tail
	sub	\$16,$len
	jmp	.Lcbc_enc_loop
.align 16
.Lcbc_enc_loop:
	movups	($inp),$inout1		# load input
	lea	16($inp),$inp
	pxor	$inout1,$inout0
___
	&aesni_generate1("enc",$key,$rounds);
$code.=<<___;
	sub	\$16,$len
	lea	16($out),$out
	mov	$rnds_,$rounds		# restore $rounds
	mov	$key_,$key		# restore $key
	movups	$inout0,-16($out)	# store output
	jnc	.Lcbc_enc_loop
	add	\$16,$len
	jnz	.Lcbc_enc_tail
	movups	$inout0,($ivp)
	jmp	.Lcbc_ret

.Lcbc_enc_tail:
	mov	$len,%rcx	# zaps $key
	xchg	$inp,$out	# $inp is %rsi and $out is %rdi now
	.long	0x9066A4F3	# rep movsb
	mov	\$16,%ecx	# zero tail
	sub	$len,%rcx
	xor	%eax,%eax
	.long	0x9066AAF3	# rep stosb
	lea	-16(%rdi),%rdi	# rewind $out by 1 block
	mov	$rnds_,$rounds	# restore $rounds
	mov	%rdi,%rsi	# $inp and $out are the same
	mov	$key_,$key	# restore $key
	xor	$len,$len	# len=16
	jmp	.Lcbc_enc_loop	# one more spin
#--------------------------- CBC DECRYPT ------------------------------#
.align	16
.Lcbc_decrypt:
___
$code.=<<___ if ($win64);
	lea	-0x58(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
.Lcbc_decrypt_body:
___
$code.=<<___;
	movups	($ivp),$iv
	sub	\$0x40,$len
	mov	$rnds_,$rounds
	jbe	.Lcbc_dec_tail
	jmp	.Lcbc_dec_loop3
.align 16
.Lcbc_dec_loop3:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	movaps	$inout0,$in0
	movaps	$inout1,$in1
	movaps	$inout2,$in2
	call	_aesni_decrypt3
	sub	\$0x30,$len
	lea	0x30($inp),$inp
	lea	0x30($out),$out
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movaps	$in2,$iv
	pxor	$in1,$inout2
	movups	$inout0,-0x30($out)
	mov	$rnds_,$rounds	# restore $rounds
	movups	$inout1,-0x20($out)
	mov	$key_,$key	# restore $key
	movups	$inout2,-0x10($out)
	ja	.Lcbc_dec_loop3

.Lcbc_dec_tail:
	add	\$0x40,$len
	movups	$iv,($ivp)
	jz	.Lcbc_dec_ret

	movups	($inp),$inout0
	cmp	\$0x10,$len
	movaps	$inout0,$in0
	jbe	.Lcbc_dec_one
	movups	0x10($inp),$inout1
	cmp	\$0x20,$len
	movaps	$inout1,$in1
	jbe	.Lcbc_dec_two
	movups	0x20($inp),$inout2
	cmp	\$0x30,$len
	movaps	$inout2,$in2
	jbe	.Lcbc_dec_three
	movups	0x30($inp),$inout3
	call	_aesni_decrypt4
	pxor	$iv,$inout0
	movups	0x30($inp),$iv
	pxor	$in0,$inout1
	movups	$inout0,($out)
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	pxor	$in2,$inout3
	movups	$inout2,0x20($out)
	movaps	$inout3,$inout0
	lea	0x30($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_one:
___
	&aesni_generate1("dec",$key,$rounds);
$code.=<<___;
	pxor	$iv,$inout0
	movaps	$in0,$iv
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_two:
	call	_aesni_decrypt3
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	movaps	$in1,$iv
	movaps	$inout1,$inout0
	lea	0x10($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_three:
	call	_aesni_decrypt3
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	movaps	$in2,$iv
	movaps	$inout2,$inout0
	lea	0x20($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_tail_collected:
	and	\$15,$len
	movups	$iv,($ivp)
	jnz	.Lcbc_dec_tail_partial
	movups	$inout0,($out)
	jmp	.Lcbc_dec_ret
.Lcbc_dec_tail_partial:
	movaps	$inout0,$reserved(%rsp)
	mov	$out,%rdi
	mov	$len,%rcx
	lea	$reserved(%rsp),%rsi
	.long	0x9066A4F3	# rep movsb

.Lcbc_dec_ret:
___
$code.=<<___ if ($win64);
	movaps	(%rsp),%xmm6
	movaps	0x10(%rsp),%xmm7
	movaps	0x20(%rsp),%xmm8
	movaps	0x30(%rsp),%xmm9
	lea	0x58(%rsp),%rsp
___
$code.=<<___;
.Lcbc_ret:
	ret
.size	${PREFIX}_cbc_encrypt,.-${PREFIX}_cbc_encrypt
___

# int $PREFIX_set_[en|de]crypt_key (const unsigned char *userKey,
#				int bits, AES_KEY *key)
{ my ($inp,$bits,$key) = @_4args;
  $bits =~ s/%r/%e/;

$code.=<<___;
.globl	${PREFIX}_set_decrypt_key
.type	${PREFIX}_set_decrypt_key,\@abi-omnipotent
.align	16
${PREFIX}_set_decrypt_key:
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
	call	_aesni_set_encrypt_key
	shl	\$4,$bits		# rounds-1 after _aesni_set_encrypt_key
	test	%eax,%eax
	jnz	.Ldec_key_ret
	lea	16($key,$bits),$inp	# points at the end of key schedule

	$movkey	($key),%xmm0		# just swap
	$movkey	($inp),%xmm1
	$movkey	%xmm0,($inp)
	$movkey	%xmm1,($key)
	lea	16($key),$key
	lea	-16($inp),$inp

.Ldec_key_inverse:
	$movkey	($key),%xmm0		# swap and inverse
	$movkey	($inp),%xmm1
	aesimc	%xmm0,%xmm0
	aesimc	%xmm1,%xmm1
	lea	16($key),$key
	lea	-16($inp),$inp
	cmp	$key,$inp
	$movkey	%xmm0,16($inp)
	$movkey	%xmm1,-16($key)
	ja	.Ldec_key_inverse

	$movkey	($key),%xmm0		# inverse middle
	aesimc	%xmm0,%xmm0
	$movkey	%xmm0,($inp)
.Ldec_key_ret:
	add	\$8,%rsp
	ret
.LSEH_end_set_decrypt_key:
.size	${PREFIX}_set_decrypt_key,.-${PREFIX}_set_decrypt_key
___

# This is based on submission by
#
#	Huang Ying <ying.huang@intel.com>
#	Vinodh Gopal <vinodh.gopal@intel.com>
#	Kahraman Akdemir
#
# Agressively optimized in respect to aeskeygenassist's critical path
# and is contained in %xmm0-5 to meet Win64 ABI requirement.
#
$code.=<<___;
.globl	${PREFIX}_set_encrypt_key
.type	${PREFIX}_set_encrypt_key,\@abi-omnipotent
.align	16
${PREFIX}_set_encrypt_key:
_aesni_set_encrypt_key:
	.byte	0x48,0x83,0xEC,0x08	# sub rsp,8
	test	$inp,$inp
	mov	\$-1,%rax
	jz	.Lenc_key_ret
	test	$key,$key
	jz	.Lenc_key_ret

	movups	($inp),%xmm0		# pull first 128 bits of *userKey
	pxor	%xmm4,%xmm4		# low dword of xmm4 is assumed 0
	lea	16($key),%rax
	cmp	\$256,$bits
	je	.L14rounds
	cmp	\$192,$bits
	je	.L12rounds
	cmp	\$128,$bits
	jne	.Lbad_keybits

.L10rounds:
	mov	\$9,$bits			# 10 rounds for 128-bit key
	$movkey	%xmm0,($key)			# round 0
	aeskeygenassist	\$0x1,%xmm0,%xmm1	# round 1
	call		.Lkey_expansion_128_cold
	aeskeygenassist	\$0x2,%xmm0,%xmm1	# round 2
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x4,%xmm0,%xmm1	# round 3
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x8,%xmm0,%xmm1	# round 4
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x10,%xmm0,%xmm1	# round 5
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x20,%xmm0,%xmm1	# round 6
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x40,%xmm0,%xmm1	# round 7
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x80,%xmm0,%xmm1	# round 8
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x1b,%xmm0,%xmm1	# round 9
	call		.Lkey_expansion_128
	aeskeygenassist	\$0x36,%xmm0,%xmm1	# round 10
	call		.Lkey_expansion_128
	$movkey	%xmm0,(%rax)
	mov	$bits,80(%rax)	# 240(%rdx)
	xor	%eax,%eax
	jmp	.Lenc_key_ret

.align	16
.L12rounds:
	movq	16($inp),%xmm2			# remaining 1/3 of *userKey
	mov	\$11,$bits			# 12 rounds for 192
	$movkey	%xmm0,($key)			# round 0
	aeskeygenassist	\$0x1,%xmm2,%xmm1	# round 1,2
	call		.Lkey_expansion_192a_cold
	aeskeygenassist	\$0x2,%xmm2,%xmm1	# round 2,3
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x4,%xmm2,%xmm1	# round 4,5
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x8,%xmm2,%xmm1	# round 5,6
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x10,%xmm2,%xmm1	# round 7,8
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x20,%xmm2,%xmm1	# round 8,9
	call		.Lkey_expansion_192b
	aeskeygenassist	\$0x40,%xmm2,%xmm1	# round 10,11
	call		.Lkey_expansion_192a
	aeskeygenassist	\$0x80,%xmm2,%xmm1	# round 11,12
	call		.Lkey_expansion_192b
	$movkey	%xmm0,(%rax)
	mov	$bits,48(%rax)	# 240(%rdx)
	xor	%rax, %rax
	jmp	.Lenc_key_ret

.align	16
.L14rounds:
	movups	16($inp),%xmm2			# remaning half of *userKey
	mov	\$13,$bits			# 14 rounds for 256
	lea	16(%rax),%rax
	$movkey	%xmm0,($key)			# round 0
	$movkey	%xmm2,16($key)			# round 1
	aeskeygenassist	\$0x1,%xmm2,%xmm1	# round 2
	call		.Lkey_expansion_256a_cold
	aeskeygenassist	\$0x1,%xmm0,%xmm1	# round 3
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x2,%xmm2,%xmm1	# round 4
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x2,%xmm0,%xmm1	# round 5
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x4,%xmm2,%xmm1	# round 6
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x4,%xmm0,%xmm1	# round 7
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x8,%xmm2,%xmm1	# round 8
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x8,%xmm0,%xmm1	# round 9
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x10,%xmm2,%xmm1	# round 10
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x10,%xmm0,%xmm1	# round 11
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x20,%xmm2,%xmm1	# round 12
	call		.Lkey_expansion_256a
	aeskeygenassist	\$0x20,%xmm0,%xmm1	# round 13
	call		.Lkey_expansion_256b
	aeskeygenassist	\$0x40,%xmm2,%xmm1	# round 14
	call		.Lkey_expansion_256a
	$movkey	%xmm0,(%rax)
	mov	$bits,16(%rax)	# 240(%rdx)
	xor	%rax,%rax
	jmp	.Lenc_key_ret

.align	16
.Lbad_keybits:
	mov	\$-2,%rax
.Lenc_key_ret:
	add	\$8,%rsp
	ret
.LSEH_end_set_encrypt_key:

.align	16
.Lkey_expansion_128:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_128_cold:
	shufps	\$0b00010000,%xmm0,%xmm4
	pxor	%xmm4, %xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	pxor	%xmm4, %xmm0
	pshufd	\$0b11111111,%xmm1,%xmm1	# critical path
	pxor	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_192a:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_192a_cold:
	movaps	%xmm2, %xmm5
.Lkey_expansion_192b_warm:
	shufps	\$0b00010000,%xmm0,%xmm4
	movaps	%xmm2,%xmm3
	pxor	%xmm4,%xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	pslldq	\$4,%xmm3
	pxor	%xmm4,%xmm0
	pshufd	\$0b01010101,%xmm1,%xmm1	# critical path
	pxor	%xmm3,%xmm2
	pxor	%xmm1,%xmm0
	pshufd	\$0b11111111,%xmm0,%xmm3
	pxor	%xmm3,%xmm2
	ret

.align 16
.Lkey_expansion_192b:
	movaps	%xmm0,%xmm3
	shufps	\$0b01000100,%xmm0,%xmm5
	$movkey	%xmm5,(%rax)
	shufps	\$0b01001110,%xmm2,%xmm3
	$movkey	%xmm3,16(%rax)
	lea	32(%rax),%rax
	jmp	.Lkey_expansion_192b_warm

.align	16
.Lkey_expansion_256a:
	$movkey	%xmm2,(%rax)
	lea	16(%rax),%rax
.Lkey_expansion_256a_cold:
	shufps	\$0b00010000,%xmm0,%xmm4
	pxor	%xmm4,%xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	pxor	%xmm4,%xmm0
	pshufd	\$0b11111111,%xmm1,%xmm1	# critical path
	pxor	%xmm1,%xmm0
	ret

.align 16
.Lkey_expansion_256b:
	$movkey	%xmm0,(%rax)
	lea	16(%rax),%rax

	shufps	\$0b00010000,%xmm2,%xmm4
	pxor	%xmm4,%xmm2
	shufps	\$0b10001100,%xmm2,%xmm4
	pxor	%xmm4,%xmm2
	pshufd	\$0b10101010,%xmm1,%xmm1	# critical path
	pxor	%xmm1,%xmm2
	ret
.size	${PREFIX}_set_encrypt_key,.-${PREFIX}_set_encrypt_key
___
}

$code.=<<___;
.asciz  "AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	cbc_se_handler,\@abi-omnipotent
.align	16
cbc_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	152($context),%rax	# pull context->Rsp
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lcbc_decrypt(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<"prologue" label
	jb	.Lin_prologue

	lea	.Lcbc_decrypt_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<cbc_decrypt_body
	jb	.Lrestore_rax

	lea	.Lcbc_ret(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>="epilogue" label
	jae	.Lin_prologue

	lea	0(%rax),%rsi		# top of stack
	lea	512($context),%rdi	# &context.Xmm6
	mov	\$8,%ecx		# 4*sizeof(%xmm0)/sizeof(%rax)
	.long	0xa548f3fc		# cld; rep movsq
	lea	0x58(%rax),%rax		# adjust stack pointer
	jmp	.Lin_prologue

.Lrestore_rax:
	mov	120($context),%rax
.Lin_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	cbc_se_handler,.-cbc_se_handler

.type	ecb_se_handler,\@abi-omnipotent
.align	16
ecb_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	152($context),%rax	# pull context->Rsp
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

.Lcommon_seh_exit:

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	cbc_se_handler,.-cbc_se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_${PREFIX}_ecb_encrypt
	.rva	.LSEH_end_${PREFIX}_ecb_encrypt
	.rva	.LSEH_info_ecb

	.rva	.LSEH_begin_${PREFIX}_cbc_encrypt
	.rva	.LSEH_end_${PREFIX}_cbc_encrypt
	.rva	.LSEH_info_cbc

	.rva	${PREFIX}_set_decrypt_key
	.rva	.LSEH_end_set_decrypt_key
	.rva	.LSEH_info_key

	.rva	${PREFIX}_set_encrypt_key
	.rva	.LSEH_end_set_encrypt_key
	.rva	.LSEH_info_key
.section	.xdata
.align	8
.LSEH_info_ecb:
	.byte	9,0,0,0
	.rva	ecb_se_handler
.LSEH_info_cbc:
	.byte	9,0,0,0
	.rva	cbc_se_handler
.LSEH_info_key:
	.byte	0x01,0x04,0x01,0x00
	.byte	0x04,0x02,0x00,0x00
___
}

sub rex {
 local *opcode=shift;
 my ($dst,$src)=@_;

   if ($dst>=8 || $src>=8) {
	$rex=0x40;
	$rex|=0x04 if($dst>=8);
	$rex|=0x01 if($src>=8);
	push @opcode,$rex;
   }
}

sub aesni {
  my $line=shift;
  my @opcode=(0x66);

    if ($line=~/(aeskeygenassist)\s+\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
	rex(\@opcode,$4,$3);
	push @opcode,0x0f,0x3a,0xdf;
	push @opcode,0xc0|($3&7)|(($4&7)<<3);	# ModR/M
	my $c=$2;
	push @opcode,$c=~/^0/?oct($c):$c;
	return ".byte\t".join(',',@opcode);
    }
    elsif ($line=~/(aes[a-z]+)\s+%xmm([0-9]+),\s*%xmm([0-9]+)/) {
	my %opcodelet = (
		"aesimc" => 0xdb,
		"aesenc" => 0xdc,	"aesenclast" => 0xdd,
		"aesdec" => 0xde,	"aesdeclast" => 0xdf
	);
	return undef if (!defined($opcodelet{$1}));
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x38,$opcodelet{$1};
	push @opcode,0xc0|($2&7)|(($3&7)<<3);	# ModR/M
	return ".byte\t".join(',',@opcode);
    }
    return $line;
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
$code =~ s/\b(aes.*%xmm[0-9]+).*$/aesni($1)/gem;

print $code;

close STDOUT;
