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
#
# TODO:
# - Win64 SEH handlers;

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

$code=".text\n";

$rounds="%eax";	# input to and changed by aesni_[en|de]cryptN !!!

# this is natural argument order for public $PREFIX_*crypt...
$inp="%rdi";
$out="%rsi";
# ... and for $PREFIX_[ebc|cbc]_encrypt in particular.
$len="%rdx";
$key="%rcx";	# input to and changed by aesni_[en|de]cryptN !!!
$ivp="%r8";	# cbc

$rnds_="%r10d";	# backup copy for $rounds
$key_="%r11";	# backup copy for $key

# %xmm register layout
$inout0="%xmm0";	$inout1="%xmm1";
$inout2="%xmm2";	$inout3="%xmm3";
$inout4="%xmm4";	$inout5="%xmm5";
$rndkey0="%xmm6";	$rndkey1="%xmm7";

$iv="%xmm8";
$in0="%xmm9";	$in1="%xmm10";
$in2="%xmm11";	$in3="%xmm12";
$in4="%xmm13";	$in5="%xmm14";

# Inline version of internal aesni_[en|de]crypt1.
#
# Why folded loop? Because aes[enc|dec] is slow enough to accommodate
# cycles which take care of loop variables...
{ my $sn;
sub aesni_encrypt1 {
my ($data,$rndkey0,$rndkey1,$key,$rounds)=@_;
++$sn;
$code.=<<___;
	$movkey	($key),$rndkey0
	$movkey	16($key),$rndkey1
	lea	16($key),$key
	pxor	$rndkey0,$data
	dec	$rounds
	jmp	.Loop_enc1_$sn
.align	16
.Loop_enc1_$sn:
	aesenc	$rndkey1,$data
	dec	$rounds
	lea	16($key),$key
	$movkey	($key),$rndkey1
	jnz	.Loop_enc1_$sn	# loop body is 16 bytes

	aesenclast	$rndkey1,$data
___
}}
{ my $sn;
sub aesni_decrypt1 {
my ($data,$rndkey0,$rndkey1,$key,$rounds)=@_;
++$sn;
$code.=<<___;
	$movkey	($key),$rndkey0
	$movkey	16($key),$rndkey1
	lea	16($key),$key
	pxor	$rndkey0,$data
	dec	$rounds
	jmp	.Loop_dec1_$sn
.align	16
.Loop_dec1_$sn:
	aesdec	$rndkey1,$data
	dec	$rounds
	lea	16($key),$key
	$movkey	($key),$rndkey1
	jnz	.Loop_dec1_$sn	# loop body is 16 bytes

	aesdeclast	$rndkey1,$data
___
}}

# void $PREFIX_encrypt (const void *inp,void *out,const AES_KEY *key);
#
$code.=<<___;
.globl	${PREFIX}_encrypt
.type	${PREFIX}_encrypt,\@function,3
.align	16
${PREFIX}_encrypt:
	movups	($inp),%xmm0		# load input
	mov	240(%rdx),$rounds	# pull $rounds
___
	&aesni_encrypt1("%xmm0","%xmm1","%xmm2","%rdx",$rounds);
$code.=<<___;
	movups	%xmm0,(%rsi)		# output
	ret
.size	${PREFIX}_encrypt,.-${PREFIX}_encrypt
___

# void $PREFIX_decrypt (const void *inp,void *out,const AES_KEY *key);
#
$code.=<<___;
.globl	${PREFIX}_decrypt
.type	${PREFIX}_decrypt,\@function,3
.align	16
${PREFIX}_decrypt:
	movups	($inp),%xmm0		# load input
	mov	240(%rdx),$rounds	# pull $rounds
___
	&aesni_decrypt1("%xmm0","%xmm1","%xmm2","%rdx",$rounds);
$code.=<<___;
	movups	%xmm0,($out)		# output
	ret
.size	${PREFIX}_decrypt, .-${PREFIX}_decrypt
___

# _aesni_[en|de]crypt6 are private interfaces, 6 denotes interleave
# factor. Why 6x? Because aes[enc|dec] latency is 6 and 6x interleave
# provides optimal utilization, so that subroutine's throughput is
# virtually same for *any* number [naturally up to 6] of input blocks
# as for non-interleaved subroutine. This is why it handles even
# double-, tripple-, quad- and penta-block inputs. Larger interleave
# factor, e.g. 8x, would perform suboptimally on these shorter inputs...
sub aesni_generate6 {
my $dir=shift;
# As already mentioned it takes in $key and $rounds, which are *not*
# preserved. $inout[0-5] is cipher/clear text...
$code.=<<___;
.type	_aesni_${dir}rypt6,\@abi-omnipotent
.align	16
_aesni_${dir}rypt6:
	$movkey	($key),$rndkey0
	$movkey	16($key),$rndkey1
	shr	\$1,$rounds
	lea	32($key),$key
	dec	$rounds
	pxor	$rndkey0,$inout0
	pxor	$rndkey0,$inout1
	pxor	$rndkey0,$inout2
	pxor	$rndkey0,$inout3
	pxor	$rndkey0,$inout4
	pxor	$rndkey0,$inout5
	jmp	.L${dir}_loop6
.align	16
.L${dir}_loop6:
	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	dec		$rounds
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
	aes${dir}	$rndkey0,$inout0
	$movkey		16($key),$rndkey1
	aes${dir}	$rndkey0,$inout1
	lea		32($key),$key
	aes${dir}	$rndkey0,$inout2
	aes${dir}	$rndkey0,$inout3
	aes${dir}	$rndkey0,$inout4
	aes${dir}	$rndkey0,$inout5
	jnz		.L${dir}_loop6
	aes${dir}	$rndkey1,$inout0
	$movkey		($key),$rndkey0
	aes${dir}	$rndkey1,$inout1
	aes${dir}	$rndkey1,$inout2
	aes${dir}	$rndkey1,$inout3
	aes${dir}	$rndkey1,$inout4
	aes${dir}	$rndkey1,$inout5
	aes${dir}last	$rndkey0,$inout0
	aes${dir}last	$rndkey0,$inout1
	aes${dir}last	$rndkey0,$inout2
	aes${dir}last	$rndkey0,$inout3
	aes${dir}last	$rndkey0,$inout4
	aes${dir}last	$rndkey0,$inout5
	ret
.size	_aesni_${dir}rypt6,.-_aesni_${dir}rypt6
___
}
&aesni_generate6("enc");
&aesni_generate6("dec");

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
	jb	.Lecb_abort
___
$code.=<<___ if ($win64);
	lea	-0x28(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,16(%rsp)
___
$code.=<<___;
	mov	240($key),$rounds	# pull $rounds
	and	\$-16,$len
	mov	$key,$key_		# backup $key
	test	%r8d,%r8d
	mov	$rounds,$rnds_		# backup $rounds
	jz	.Lecb_decrypt
#--------------------------- ECB ENCRYPT ------------------------------#
	sub	\$0x60,$len
	jc	.Lecb_enc_tail
	jmp	.Lecb_enc_loop6
.align 16
.Lecb_enc_loop6:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	movups	0x30($inp),$inout3
	movups	0x40($inp),$inout4
	movups	0x50($inp),$inout5
	call	_aesni_encrypt6
	movups	$inout0,($out)
	sub	\$0x60,$len
	movups	$inout1,0x10($out)
	lea	0x60($inp),$inp
	movups	$inout2,0x20($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout3,0x30($out)
	mov	$key_,$key		# restore $key
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	lea	0x60($out),$out
	jnc	.Lecb_enc_loop6

.Lecb_enc_tail:
	add	\$0x60,$len
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
	cmp	\$0x40,$len
	movups	0x30($inp),$inout3
	je	.Lecb_enc_four
	movups	0x40($inp),$inout4
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_one:
___
	&aesni_encrypt1($inout0,$rndkey0,$rndkey1,$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_two:
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_three:
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	jmp	.Lecb_ret
.align	16
.Lecb_enc_four:
	call	_aesni_encrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	jmp	.Lecb_ret
#--------------------------- ECB DECRYPT ------------------------------#
.align	16
.Lecb_decrypt:
	sub	\$0x60,$len
	jc	.Lecb_dec_tail
	jmp	.Lecb_dec_loop6
.align 16
.Lecb_dec_loop6:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	movups	0x30($inp),$inout3
	movups	0x40($inp),$inout4
	movups	0x50($inp),$inout5
	call	_aesni_decrypt6
	movups	$inout0,($out)
	sub	\$0x60,$len
	movups	$inout1,0x10($out)
	lea	0x60($inp),$inp
	movups	$inout2,0x20($out)
	mov	$rnds_,$rounds		# restore $rounds
	movups	$inout3,0x30($out)
	mov	$key_,$key		# restore $key
	movups	$inout4,0x40($out)
	movups	$inout5,0x50($out)
	lea	0x60($out),$out
	jnc	.Lecb_dec_loop6

.Lecb_dec_tail:
	add	\$0x60,$len
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
	cmp	\$0x40,$len
	movups	0x30($inp),$inout3
	je	.Lecb_dec_four
	movups	0x40($inp),$inout4
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)
	movups	$inout4,0x40($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_one:
___
	&aesni_decrypt1($inout0,$rndkey0,$rndkey1,$key,$rounds);
$code.=<<___;
	movups	$inout0,($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_two:
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_three:
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	jmp	.Lecb_ret
.align	16
.Lecb_dec_four:
	call	_aesni_decrypt6
	movups	$inout0,($out)
	movups	$inout1,0x10($out)
	movups	$inout2,0x20($out)
	movups	$inout3,0x30($out)

.Lecb_ret:
___
$code.=<<___ if ($win64);
	movaps	(%rsp),%xmm6
	movaps	0x10(%rsp),%xmm7
	lea	0x28(%rsp),%rsp
___
$code.=<<___;
.Lecb_abort:
	ret
.size	aesni_ecb_encrypt,.-aesni_ecb_encrypt
___
}

# void $PREFIX_cbc_encrypt (const void *inp, void *out,
#			    size_t length, const AES_KEY *key,
#			    unsigned char *ivp,const int enc);
$reserved = $win64?0x90:-0x18;	# used in decrypt
$code.=<<___;
.globl	${PREFIX}_cbc_encrypt
.type	${PREFIX}_cbc_encrypt,\@function,6
.align	16
${PREFIX}_cbc_encrypt:
	test	$len,$len		# check length
	jz	.Lcbc_ret
	mov	240($key),$rounds	# pull $rounds
	mov	$key,$key_		# backup $key
	test	%r9d,%r9d
	mov	$rounds,$rnds_		# backup $rounds
	jz	.Lcbc_decrypt
#--------------------------- CBC ENCRYPT ------------------------------#
	movups	($ivp),%xmm0	# load iv as initial state
	cmp	\$16,$len
	jb	.Lcbc_enc_tail
	sub	\$16,$len
	jmp	.Lcbc_enc_loop
.align 16
.Lcbc_enc_loop:
	movups	($inp),%xmm2	# load input
	lea	16($inp),$inp
	pxor	%xmm2,%xmm0
___
	&aesni_encrypt1("%xmm0","%xmm1","%xmm2",$key,$rounds);
$code.=<<___;
	movups	%xmm0,($out)	# store output
	sub	\$16,$len
	lea	16($out),$out
	mov	$rnds_,$rounds	# restore $rounds
	mov	$key_,$key	# restore $key
	jnc	.Lcbc_enc_loop
	add	\$16,$len
	jnz	.Lcbc_enc_tail
	movups	%xmm0,($ivp)
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
	lea	-0xa8(%rsp),%rsp
	movaps	%xmm6,(%rsp)
	movaps	%xmm7,0x10(%rsp)
	movaps	%xmm8,0x20(%rsp)
	movaps	%xmm9,0x30(%rsp)
	movaps	%xmm10,0x40(%rsp)
	movaps	%xmm11,0x50(%rsp)
	movaps	%xmm12,0x60(%rsp)
	movaps	%xmm13,0x70(%rsp)
	movaps	%xmm14,0x80(%rsp)
___
$code.=<<___;
	movups	($ivp),$iv
	sub	\$0x60,$len
	jc	.Lcbc_dec_tail
	jmp	.Lcbc_dec_loop6
.align 16
.Lcbc_dec_loop6:
	movups	($inp),$inout0
	movups	0x10($inp),$inout1
	movups	0x20($inp),$inout2
	movups	0x30($inp),$inout3
	movaps	$inout0,$in0
	movups	0x40($inp),$inout4
	movaps	$inout1,$in1
	movups	0x50($inp),$inout5
	movaps	$inout2,$in2
	movaps	$inout3,$in3
	movaps	$inout4,$in4
	movaps	$inout5,$in5
	call	_aesni_decrypt6
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	sub	\$0x60,$len
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	lea	0x60($inp),$inp
	pxor	$in2,$inout3
	movups	$inout2,0x20($out)
	mov	$rnds_,$rounds	# restore $rounds
	pxor	$in3,$inout4
	movups	$inout3,0x30($out)
	mov	$key_,$key	# restore $key
	pxor	$in4,$inout5
	movups	$inout4,0x40($out)
	movaps	$in5,$iv
	movups	$inout5,0x50($out)
	lea	0x60($out),$out
	jnc	.Lcbc_dec_loop6

.Lcbc_dec_tail:
	add	\$0x60,$len
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
	cmp	\$0x40,$len
	movaps	$inout3,$in3
	jbe	.Lcbc_dec_four
	movups	0x40($inp),$inout4
	cmp	\$0x50,$len
	movaps	$inout4,$in4
	jbe	.Lcbc_dec_five
	movups	0x50($inp),$inout5
	movaps	$inout5,$in5
	call	_aesni_decrypt6
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	pxor	$in2,$inout3
	movups	$inout2,0x20($out)
	pxor	$in3,$inout4
	movups	$inout3,0x30($out)
	pxor	$in4,$inout5
	movups	$inout4,0x40($out)
	movaps	$in5,$iv
	movaps	$inout5,$inout0
	lea	0x50($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_one:
___
	&aesni_decrypt1($inout0,$rndkey0,$rndkey1,$key,$rounds);
$code.=<<___;
	pxor	$iv,$inout0
	movaps	$in0,$iv
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_two:
	call	_aesni_decrypt6
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	movaps	$in1,$iv
	movaps	$inout1,$inout0
	lea	0x10($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_three:
	call	_aesni_decrypt6
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
.Lcbc_dec_four:
	call	_aesni_decrypt6
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	pxor	$in2,$inout3
	movups	$inout2,0x20($out)
	movaps	$in3,$iv
	movaps	$inout3,$inout0
	lea	0x30($out),$out
	jmp	.Lcbc_dec_tail_collected
.align	16
.Lcbc_dec_five:
	call	_aesni_decrypt6
	pxor	$iv,$inout0
	pxor	$in0,$inout1
	movups	$inout0,($out)
	pxor	$in1,$inout2
	movups	$inout1,0x10($out)
	pxor	$in2,$inout3
	movups	$inout2,0x20($out)
	pxor	$in3,$inout4
	movups	$inout3,0x30($out)
	movaps	$in4,$iv
	movaps	$inout4,$inout0
	lea	0x40($out),$out
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
	movaps	0x40(%rsp),%xmm10
	movaps	0x50(%rsp),%xmm11
	movaps	0x60(%rsp),%xmm12
	movaps	0x70(%rsp),%xmm13
	movaps	0x80(%rsp),%xmm14
	lea	0xa8(%rsp),%rsp
___
$code.=<<___;
.Lcbc_ret:
	ret
.size	${PREFIX}_cbc_encrypt,.-${PREFIX}_cbc_encrypt
___

{
# this is natural argument order for $PREFIX_set_[en|de]crypt_key 
my $inp="%rdi";
my $bits="%esi";
my $key="%rdx";

# int $PREFIX_set_encrypt_key (const unsigned char *userKey, int bits,
#                              AES_KEY *key)
$code.=<<___;
.globl	${PREFIX}_set_encrypt_key
.type	${PREFIX}_set_encrypt_key,\@function,3
.align	16
${PREFIX}_set_encrypt_key:
	call	_aesni_set_encrypt_key
	ret
.size	${PREFIX}_set_encrypt_key,.-${PREFIX}_set_encrypt_key
___
# int $PREFIX_set_decrypt_key(const unsigned char *userKey, const int bits,
#                               AES_KEY *key)
$code.=<<___;
.globl	${PREFIX}_set_decrypt_key
.type	${PREFIX}_set_decrypt_key,\@function,3
.align	16
${PREFIX}_set_decrypt_key:
	call	_aesni_set_encrypt_key
	shl	\$4,%esi	# actually rounds after _aesni_set_encrypt_key
	test	%eax,%eax
	jnz	.Ldec_key_ret
	lea	(%rdx,%rsi),%rsi# points at the end of key schedule

	$movkey	(%rdx),%xmm0	# just swap
	$movkey	(%rsi),%xmm1
	$movkey	%xmm0,(%rsi)
	$movkey	%xmm1,(%rdx)
	lea	16(%rdx),%rdx
	lea	-16(%rsi),%rsi
	jmp	.Ldec_key_inverse
.align 16
.Ldec_key_inverse:
	$movkey	(%rdx),%xmm0	# swap and inverse
	$movkey	(%rsi),%xmm1
	aesimc	%xmm0,%xmm0
	aesimc	%xmm1,%xmm1
	lea	16(%rdx),%rdx
	lea	-16(%rsi),%rsi
	cmp	%rdx,%rsi
	$movkey	%xmm0,16(%rsi)
	$movkey	%xmm1,-16(%rdx)
	ja	.Ldec_key_inverse

	$movkey	(%rdx),%xmm0	# inverse middle
	aesimc	%xmm0,%xmm0
	$movkey	%xmm0,(%rsi)
.Ldec_key_ret:
	ret
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
.type	_aesni_set_encrypt_key,\@abi-omnipotent
.align	16
_aesni_set_encrypt_key:
	test	%rdi,%rdi
	jz	.Lbad_pointer
	test	%rdx,%rdx
	jz	.Lbad_pointer

	movups	(%rdi),%xmm0		# pull first 128 bits of *userKey
	pxor	%xmm4,%xmm4		# low dword of xmm4 is assumed 0
	lea	16(%rdx),%rcx
	cmp	\$256,%esi
	je	.L14rounds
	cmp	\$192,%esi
	je	.L12rounds
	cmp	\$128,%esi
	jne	.Lbad_keybits

.L10rounds:
	mov	\$10,%esi			# 10 rounds for 128-bit key
	$movkey	%xmm0,(%rdx)			# round 0
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
	$movkey	%xmm0,(%rcx)
	mov	%esi,80(%rcx)	# 240(%rdx)
	xor	%eax,%eax
	ret

.align	16
.Lkey_expansion_128:
	$movkey	%xmm0,(%rcx)
	lea	16(%rcx),%rcx
.Lkey_expansion_128_cold:
	shufps	\$0b00010000,%xmm0,%xmm4
	pxor	%xmm4, %xmm0
	shufps	\$0b10001100,%xmm0,%xmm4
	pxor	%xmm4, %xmm0
	pshufd	\$0b11111111,%xmm1,%xmm1	# critical path
	pxor	%xmm1,%xmm0
	ret

.align	16
.L12rounds:
	movq	16(%rdi),%xmm2			# remaining 1/3 of *userKey
	mov	\$12,%esi			# 12 rounds for 192
	$movkey	%xmm0,(%rdx)			# round 0
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
	$movkey	%xmm0,(%rcx)
	mov	%esi,48(%rcx)	# 240(%rdx)
	xor	%rax, %rax
	ret

.align 16
.Lkey_expansion_192a:
	$movkey	%xmm0,(%rcx)
	lea	16(%rcx),%rcx
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
	$movkey	%xmm5,(%rcx)
	shufps	\$0b01001110,%xmm2,%xmm3
	$movkey	%xmm3,16(%rcx)
	lea	32(%rcx),%rcx
	jmp	.Lkey_expansion_192b_warm

.align	16
.L14rounds:
	movups	16(%rdi),%xmm2			# remaning half of *userKey
	mov	\$14,%esi			# 14 rounds for 256
	lea	16(%rcx),%rcx
	$movkey	%xmm0,(%rdx)			# round 0
	$movkey	%xmm2,16(%rdx)			# round 1
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
	$movkey	%xmm0,(%rcx)
	mov	%esi,16(%rcx)	# 240(%rdx)
	xor	%rax,%rax
	ret

.align	16
.Lkey_expansion_256a:
	$movkey	%xmm2,(%rcx)
	lea	16(%rcx),%rcx
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
	$movkey	%xmm0,(%rcx)
	lea	16(%rcx),%rcx

	shufps	\$0b00010000,%xmm2,%xmm4
	pxor	%xmm4,%xmm2
	shufps	\$0b10001100,%xmm2,%xmm4
	pxor	%xmm4,%xmm2
	pshufd	\$0b10101010,%xmm1,%xmm1	# critical path
	pxor	%xmm1,%xmm2
	ret

.align	16
.Lbad_pointer:
	mov \$-1, %rax
	ret
.Lbad_keybits:
	mov \$-2, %rax
	ret
.size	_aesni_set_encrypt_key,.-_aesni_set_encrypt_key
___
}

$code.=<<___;
.asciz  "AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
___

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
