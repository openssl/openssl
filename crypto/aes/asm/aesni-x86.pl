#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements support for Intel AES-NI extension. In
# OpenSSL context it's used with Intel engine, but can also be used as
# drop-in replacement for crypto/aes/asm/aes-586.pl [see below for
# details].

$PREFIX="aesni";	# if $PREFIX is set to "AES", the script
			# generates drop-in replacement for
			# crypto/aes/asm/aes-586.pl:-)

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

$movekey = eval($RREFIX eq "aseni" ? "*movaps" : "*movups");

$len="eax";
$rounds="ecx";
$key="edx";
$inp="esi";
$out="edi";
$rounds_="ebx";	# backup copy for $rounds
$key_="ebp";	# backup copy for $key

$inout0="xmm0";
$inout1="xmm1";
$inout2="xmm2";
$rndkey0="xmm3";
$rndkey1="xmm4";
$ivec="xmm5";
$in0="xmm6";
$in1="xmm7";	$inout3="xmm7";

# Inline version of internal aesni_[en|de]crypt1
sub aesni_inline_generate1
{ my $p=shift;

    &$movekey		($rndkey0,&QWP(0,$key));
    &$movekey		($rndkey1,&QWP(16,$key));
    &lea		($key,&DWP(32,$key));
    &pxor		($inout0,$rndkey0);
    &set_label("${p}1_loop");
	eval"&aes${p}	($inout0,$rndkey1)";
	&dec		($rounds);
	&$movekey	($rndkey1,&QWP(0,$key));
	&lea		($key,&DWP(16,$key));
    &jnz		(&label("${p}1_loop"));
    eval"&aes${p}last	($inout0,$rndkey1)";
}

sub aesni_generate1	# fully unrolled loop
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt1");
	&$movekey	($rndkey0,&QWP(0,$key));
	&$movekey	($rndkey1,&QWP(0x10,$key));
	&cmp		($rounds,11);
	&pxor		($inout0,$rndkey0);
	&$movekey	($rndkey0,&QWP(0x20,$key));
	&lea		($key,&DWP(0x30,$key));
	&jb		(&label("${p}128"));
	&lea		($key,&DWP(0x20,$key));
	&je		(&label("${p}192"));
	&lea		($key,&DWP(0x20,$key));
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(-0x40,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(-0x30,$key));
    &set_label("${p}192");
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(-0x20,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(-0x10,$key));
    &set_label("${p}128");
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x10,$key));
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x20,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x30,$key));
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x40,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x50,$key));
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey1,&QWP(0x60,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&$movekey	($rndkey0,&QWP(0x70,$key));
	eval"&aes${p}	($inout0,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt1");
}

# void $PREFIX_encrypt (const void *inp,void *out,const AES_KEY *key);
# &aesni_generate1("dec");
&function_begin_B("${PREFIX}_encrypt");
	&mov	("eax",&wparam(0));
	&mov	($key,&wparam(2));
	&movups	($inout0,&QWP(0,"eax"));
	&mov	($rounds,&DWP(240,$key));
	&mov	("eax",&wparam(1));
	&aesni_inline_generate1("enc");	# &call	("_aesni_encrypt1");
	&movups	(&QWP(0,"eax"),$inout0);
	&ret	();
&function_end_B("${PREFIX}_encrypt");

# void $PREFIX_decrypt (const void *inp,void *out,const AES_KEY *key);
# &aesni_generate1("dec");
&function_begin_B("${PREFIX}_decrypt");
	&mov	("eax",&wparam(0));
	&mov	($key,&wparam(2));
	&movups	($inout0,&QWP(0,"eax"));
	&mov	($rounds,&DWP(240,$key));
	&mov	("eax",&wparam(1));
	&aesni_inline_generate1("dec");	# &call	("_aesni_decrypt1");
	&movups	(&QWP(0,"eax"),$inout0);
	&ret	();
&function_end_B("${PREFIX}_decrypt");

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
sub aesni_generate3
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt3");
	&$movekey	($rndkey0,&QWP(0,$key));
	&shr		($rounds,1);
	&$movekey	($rndkey1,&QWP(16,$key));
	&lea		($key,&DWP(32,$key));
	&pxor		($inout0,$rndkey0);
	&pxor		($inout1,$rndkey0);
	&pxor		($inout2,$rndkey0);
	&jmp		(&label("${p}3_loop"));
    &set_label("${p}3_loop",16);
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey0,&QWP(0,$key));
	eval"&aes${p}	($inout1,$rndkey1)";
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	&$movekey	($rndkey1,&QWP(16,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&lea		($key,&DWP(32,$key));
	eval"&aes${p}	($inout1,$rndkey0)";
	eval"&aes${p}	($inout2,$rndkey0)";
	&jnz		(&label("${p}3_loop"));
    eval"&aes${p}	($inout0,$rndkey1)";
    &$movekey		($rndkey0,&QWP(0,$key));
    eval"&aes${p}	($inout1,$rndkey1)";
    eval"&aes${p}	($inout2,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    eval"&aes${p}last	($inout1,$rndkey0)";
    eval"&aes${p}last	($inout2,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt3");
}

# 4x interleave is implemented to improve small block performance,
# most notably [and naturally] 4 block by ~30%. One can argue that one
# should have implemented 5x as well, but improvement  would be <20%,
# so it's not worth it...
sub aesni_generate4
{ my $p=shift;

    &function_begin_B("_aesni_${p}rypt4");
	&$movekey	($rndkey0,&QWP(0,$key));
	&$movekey	($rndkey1,&QWP(16,$key));
	&shr		($rounds,1);
	&lea		($key,&DWP(32,$key));
	&pxor		($inout0,$rndkey0);
	&pxor		($inout1,$rndkey0);
	&pxor		($inout2,$rndkey0);
	&pxor		($inout3,$rndkey0);
	&jmp		(&label("${p}3_loop"));
    &set_label("${p}3_loop",16);
	eval"&aes${p}	($inout0,$rndkey1)";
	&$movekey	($rndkey0,&QWP(0,$key));
	eval"&aes${p}	($inout1,$rndkey1)";
	&dec		($rounds);
	eval"&aes${p}	($inout2,$rndkey1)";
	eval"&aes${p}	($inout3,$rndkey1)";
	&$movekey	($rndkey1,&QWP(16,$key));
	eval"&aes${p}	($inout0,$rndkey0)";
	&lea		($key,&DWP(32,$key));
	eval"&aes${p}	($inout1,$rndkey0)";
	eval"&aes${p}	($inout2,$rndkey0)";
	eval"&aes${p}	($inout3,$rndkey0)";
	&jnz		(&label("${p}3_loop"));
    eval"&aes${p}	($inout0,$rndkey1)";
    &$movekey		($rndkey0,&QWP(0,$key));
    eval"&aes${p}	($inout1,$rndkey1)";
    eval"&aes${p}	($inout2,$rndkey1)";
    eval"&aes${p}	($inout3,$rndkey1)";
    eval"&aes${p}last	($inout0,$rndkey0)";
    eval"&aes${p}last	($inout1,$rndkey0)";
    eval"&aes${p}last	($inout2,$rndkey0)";
    eval"&aes${p}last	($inout3,$rndkey0)";
    &ret();
    &function_end_B("_aesni_${p}rypt4");
}
&aesni_generate3("enc") if ($PREFIX eq "aesni");
&aesni_generate3("dec");
&aesni_generate4("enc") if ($PREFIX eq "aesni");
&aesni_generate4("dec");

if ($PREFIX eq "aesni") {
# void aesni_ecb_encrypt (const void *in, void *out,
#                         size_t length, const AES_KEY *key,
#                         int enc);
&function_begin("aesni_ecb_encrypt");
	&mov	($inp,&wparam(0));
	&mov	($out,&wparam(1));
	&mov	($len,&wparam(2));
	&mov	($key,&wparam(3));
	&mov	($rounds,&wparam(4));
	&cmp	($len,16);
	&jb	(&label("ecb_ret"));
	&and	($len,-16);
	&test	($rounds,$rounds)
	&mov	($rounds,&DWP(240,$key));
	&mov	($key_,$key);		# backup $key
	&mov	($rounds_,$rounds);	# backup $rounds
	&jz	(&label("ecb_decrypt"));

	&sub	($len,0x40);
	&jbe	(&label("ecb_enc_tail"));
	&jmp	(&label("ecb_enc_loop3"));

&set_label("ecb_enc_loop3",16);
	&movups	($inout0,&QWP(0,$inp));
	&movups	($inout1,&QWP(0x10,$inp));
	&movups	($inout2,&QWP(0x20,$inp));
	&call	("_aesni_encrypt3");
	&sub	($len,0x30);
	&lea	($inp,&DWP(0x30,$inp));
	&lea	($out,&DWP(0x30,$out));
	&movups	(&QWP(-0x30,$out),$inout0);
	&mov	($key,$key_);		# restore $key
	&movups	(&QWP(-0x20,$out),$inout1);
	&mov	($rounds,$rounds_);	# restore $rounds
	&movups	(&QWP(-0x10,$out),$inout2);
	&ja	(&label("ecb_enc_loop3"));

&set_label("ecb_enc_tail");
	&add	($len,0x40);
	&jz	(&label("ecb_ret"));

	&cmp	($len,0x10);
	&movups	($inout0,&QWP(0,$inp));
	&je	(&label("ecb_enc_one"));
	&cmp	($len,0x20);
	&movups	($inout1,&QWP(0x10,$inp));
	&je	(&label("ecb_enc_two"));
	&cmp	($len,0x30);
	&movups	($inout2,&QWP(0x20,$inp));
	&je	(&label("ecb_enc_three"));
	&movups	($inout3,&QWP(0x30,$inp));
	&call	("_aesni_encrypt4");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	jmp	(&label("ecb_ret"));

&set_label("ecb_enc_one",16);
	&aesni_inline_generate1("enc");	# &call	("_aesni_encrypt1");
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_enc_two",16);
	&call	("_aesni_encrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_enc_three",16);
	&call	("_aesni_encrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_decrypt",16);
	&sub	($len,0x40);
	&jbe	(&label("ecb_dec_tail"));
	&jmp	(&label("ecb_dec_loop3"));

&set_label("ecb_dec_loop3",16);
	&movups	($inout0,&QWP(0,$inp));
	&movups	($inout1,&QWP(0x10,$inp));
	&movups	($inout2,&QWP(0x20,$inp));
	&call	("_aesni_decrypt3");
	&sub	($len,0x30);
	&lea	($inp,&DWP(0x30,$inp));
	&lea	($out,&DWP(0x30,$out));
	&movups	(&QWP(-0x30,$out),$inout0);
	&mov	($key,$key_);		# restore $key
	&movups	(&QWP(-0x20,$out),$inout1);
	&mov	($rounds,$rounds_);	# restore $rounds
	&movups	(&QWP(-0x10,$out),$inout2);
	&ja	(&label("ecb_dec_loop3"));

&set_label("ecb_dec_tail");
	&add	($len,0x40);
	&jz	(&label("ecb_ret"));

	&cmp	($len,0x10);
	&movups	($inout0,&QWP(0,$inp));
	&je	(&label("ecb_dec_one"));
	&cmp	($len,0x20);
	&movups	($inout1,&QWP(0x10,$inp));
	&je	(&label("ecb_dec_two"));
	&cmp	($len,0x30);
	&movups	($inout2,&QWP(0x20,$inp));
	&je	(&label("ecb_dec_three"));
	&movups	($inout3,&QWP(0x30,$inp));
	&call	("_aesni_decrypt4");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movups	(&QWP(0x30,$out),$inout3);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_one",16);
	&aesni_inline_generate1("dec");	# &call	("_aesni_decrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_two",16);
	&call	("_aesni_decrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&jmp	(&label("ecb_ret"));

&set_label("ecb_dec_three",16);
	&call	("_aesni_decrypt3");
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);

&set_label("ecb_ret");
&function_end("aesni_ecb_encrypt");
}

# void $PREFIX_cbc_encrypt (const void *inp, void *out,
#                           size_t length, const AES_KEY *key,
#                           unsigned char *ivp,const int enc);
&function_begin("${PREFIX}_cbc_encrypt");
	&mov	($inp,&wparam(0));
	&mov	($out,&wparam(1));
	&mov	($len,&wparam(2));
	&mov	($key,&wparam(3));
	&test	($len,$len);
	&mov	($key_,&wparam(4));
	&jz	(&label("cbc_ret"));

	&cmp	(&wparam(5),0);
	&movups	($ivec,&QWP(0,$key_));	# load IV
	&mov	($rounds,&DWP(240,$key));
	&mov	($key_,$key);		# backup $key
	&mov	($rounds_,$rounds);	# backup $rounds
	&je	(&label("cbc_decrypt"));

	&movaps	($inout0,$ivec);
	&cmp	($len,16);
	&jb	(&label("cbc_enc_tail"));
	&sub	($len,16);
	&jmp	(&label("cbc_enc_loop"));

&set_label("cbc_enc_loop",16);
	&movups	($ivec,&QWP(0,$inp));
	&lea	($inp,&DWP(16,$inp));
	&pxor	($inout0,$ivec);
	&aesni_inline_generate1("enc");	# &call	("_aesni_encrypt3");
	&sub	($len,16);
	&lea	($out,&DWP(16,$out));
	&mov	($rounds,$rounds_);	# restore $rounds
	&mov	($key,$key_);		# restore $key
	&movups	(&QWP(-16,$out),$inout0);
	&jnc	(&label("cbc_enc_loop"));
	&add	($len,16);
	&jnz	(&label("cbc_enc_tail"));
	&movaps	($ivec,$inout0);
	&jmp	(&label("cbc_ret"));

&set_label("cbc_enc_tail");
	&mov	("ecx",$len);		# zaps $rounds
	&data_word(0xA4F3F689);		# rep movsb
	&mov	("ecx",16);		# zero tail
	&sub	("ecx",$len);
	&xor	("eax","eax");		# zaps $len
	&data_word(0xAAF3F689);		# rep stosb
	&lea	($out,&DWP(-16,$out));	# rewind $out by 1 block
	&mov	($rounds,$rounds_);	# restore $rounds
	&mov	($inp,$out);		# $inp and $out are the same
	&mov	($key,$key_);		# restore $key
	&jmp	(&label("cbc_enc_loop"));

&set_label("cbc_decrypt",16);
	&sub	($len,0x40);
	&jbe	(&label("cbc_dec_tail"));
	&jmp	(&label("cbc_dec_loop3"));

&set_label("cbc_dec_loop3",16);
	&movups	($inout0,&QWP(0,$inp));
	&movups	($inout1,&QWP(0x10,$inp));
	&movups	($inout2,&QWP(0x20,$inp));
	&movaps	($in0,$inout0);
	&movaps	($in1,$inout1);
	&call	("_aesni_decrypt3");
	&sub	($len,0x30);
	&lea	($inp,&DWP(0x30,$inp));
	&lea	($out,&DWP(0x30,$out));
	&pxor	($inout0,$ivec);
	&pxor	($inout1,$in0);
	&movups	($ivec,&QWP(-0x10,$inp));
	&pxor	($inout2,$in1);
	&movups	(&QWP(-0x30,$out),$inout0);
	&mov	($rounds,$rounds_)	# restore $rounds
	&movups	(&QWP(-0x20,$out),$inout1);
	&mov	($key,$key_);		# restore $key
	&movups	(&QWP(-0x10,$out),$inout2);
	&ja	(&label("cbc_dec_loop3"));

&set_label("cbc_dec_tail");
	&add	($len,0x40);
	&jz	(&label("cbc_ret"));

	&movups	($inout0,&QWP(0,$inp));
	&cmp	($len,0x10);
	&movaps	($in0,$inout0);
	&jbe	(&label("cbc_dec_one"));
	&movups	($inout1,&QWP(0x10,$inp));
	&cmp	($len,0x20);
	&movaps	($in1,$inout1);
	&jbe	(&label("cbc_dec_two"));
	&movups	($inout2,&QWP(0x20,$inp));
	&cmp	($len,0x30);
	&jbe	(&label("cbc_dec_three"));
	&movups	($inout3,&QWP(0x30,$inp));
	&call	("_aesni_decrypt4");
	&movups	($rndkey0,&QWP(0x10,$inp));
	&movups	($rndkey1,&QWP(0x20,$inp));
	&pxor	($inout0,$ivec);
	&pxor	($inout1,$in0);
	&movups	($ivec,&QWP(0x30,$inp));
	&movups	(&QWP(0,$out),$inout0);
	&pxor	($inout2,$rndkey0);
	&pxor	($inout3,$rndkey1);
	&movups	(&QWP(0x10,$out),$inout1);
	&movups	(&QWP(0x20,$out),$inout2);
	&movaps	($inout0,$inout3);
	&lea	($out,&DWP(0x30,$out));
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_one");
	&aesni_inline_generate1("dec");	# &call	("_aesni_decrypt3");
	&pxor	($inout0,$ivec);
	&movaps	($ivec,$in0);
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_two");
	&call	("_aesni_decrypt3");
	&pxor	($inout0,$ivec);
	&pxor	($inout1,$in0);
	&movups	(&QWP(0,$out),$inout0);
	&movaps	($inout0,$inout1);
	&movaps	($ivec,$in1);
	&lea	($out,&DWP(0x10,$out));
	&jmp	(&label("cbc_dec_tail_collected"));

&set_label("cbc_dec_three");
	&call	("_aesni_decrypt3");
	&pxor	($inout0,$ivec);
	&pxor	($inout1,$in0);
	&pxor	($inout2,$in1);
	&movups	(&QWP(0,$out),$inout0);
	&movups	(&QWP(0x10,$out),$inout1);
	&movaps	($inout0,$inout2);
	&movups	($ivec,&QWP(0x20,$inp));
	&lea	($out,&DWP(0x20,$out));

&set_label("cbc_dec_tail_collected");
	&and	($len,15);
	&jnz	(&label("cbc_dec_tail_partial"));
	&movups	(&QWP(0,$out),$inout0);
	&jmp	(&label("cbc_ret"));

&set_label("cbc_dec_tail_partial");
	&mov	($key_,"esp");
	&sub	("esp",16);
	&and	("esp",-16);
	&movaps	(&QWP(0,"esp"),$inout0);
	&mov	($inp,"esp");
	&mov	("ecx",$len);
	&data_word(0xA4F3F689);		# rep movsb
	&mov	("esp",$key_);

&set_label("cbc_ret");
	&mov	($key_,&wparam(4));
	&movups	(&QWP(0,$key_),$ivec);	# output IV
&function_end("${PREFIX}_cbc_encrypt");

# Mechanical port from aesni-x86_64.pl.
#
# _aesni_set_encrypt_key is private interface,
# input:
#	"eax"	const unsigned char *userKey
#	$rounds	int bits
#	$key	AES_KEY *key
# output:
#	"eax"	return code
#	$round	rounds

&function_begin_B("_aesni_set_encrypt_key");
	&test	("eax","eax");
	&jz	(&label("bad_pointer"));
	&test	($key,$key);
	&jz	(&label("bad_pointer"));

	&movups	("xmm0",&QWP(0,"eax"));	# pull first 128 bits of *userKey
	&pxor	("xmm4","xmm4");	# low dword of xmm4 is assumed 0
	&lea	($key,&DWP(16,$key));
	&cmp	($rounds,256);
	&je	(&label("14rounds"));
	&cmp	($rounds,192);
	&je	(&label("12rounds"));
	&cmp	($rounds,128);
	&jne	(&label("bad_keybits"));

&set_label("10rounds",16);
	&mov		($rounds,9);
	&$movekey	(&QWP(-16,$key),"xmm0");	# round 0
	&aeskeygenassist("xmm1","xmm0",0x01);		# round 1
	&call		(&label("key_128_cold"));
	&aeskeygenassist("xmm1","xmm0",0x2);		# round 2
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x04);		# round 3
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x08);		# round 4
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x10);		# round 5
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x20);		# round 6
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x40);		# round 7
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x80);		# round 8
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x1b);		# round 9
	&call		(&label("key_128"));
	&aeskeygenassist("xmm1","xmm0",0x36);		# round 10
	&call		(&label("key_128"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(80,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_128",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));
&set_label("key_128_cold");
	&shufps		("xmm4","xmm0",0b00010000);
	&pxor		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100,);
	&pxor		("xmm0","xmm4");
	&pshufd		("xmm1","xmm1",0b11111111);	# critical path
	&pxor		("xmm0","xmm1");
	&ret();

&set_label("12rounds",16);
	&movq		("xmm2",&QWP(16,"eax"));	# remaining 1/3 of *userKey
	&mov		($rounds,11);
	&$movekey	(&QWP(-16,$key),"xmm0")		# round 0
	&aeskeygenassist("xmm1","xmm2",0x01);		# round 1,2
	&call		(&label("key_192a_cold"));
	&aeskeygenassist("xmm1","xmm2",0x02);		# round 2,3
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x04);		# round 4,5
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x08);		# round 5,6
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x10);		# round 7,8
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x20);		# round 8,9
	&call		(&label("key_192b"));
	&aeskeygenassist("xmm1","xmm2",0x40);		# round 10,11
	&call		(&label("key_192a"));
	&aeskeygenassist("xmm1","xmm2",0x80);		# round 11,12
	&call		(&label("key_192b"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(48,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_192a",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));
&set_label("key_192a_cold",16);
	&movaps		("xmm5","xmm2");
&set_label("key_192b_warm");
	&shufps		("xmm4","xmm0",0b00010000);
	&movaps		("xmm3","xmm2");
	&pxor		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100);
	&pslldq		("xmm3",4);
	&pxor		("xmm0","xmm4");
	&pshufd		("xmm1","xmm1",0b01010101);	# critical path
	&pxor		("xmm2","xmm3");
	&pxor		("xmm0","xmm1");
	&pshufd		("xmm3","xmm0",0b11111111);
	&pxor		("xmm2","xmm3");
	&ret();

&set_label("key_192b",16);
	&movaps		("xmm3","xmm0");
	&shufps		("xmm5","xmm0",0b01000100);
	&$movekey	(&QWP(0,$key),"xmm5");
	&shufps		("xmm3","xmm2",0b01001110);
	&$movekey	(&QWP(16,$key),"xmm3");
	&lea		($key,&DWP(32,$key));
	&jmp		(&label("key_192b_warm"));

&set_label("14rounds",16);
	&movups		("xmm2",&QWP(16,"eax"));	# remaining half of *userKey
	&mov		($rounds,13);
	&lea		($key,&DWP(16,$key));
	&$movekey	(&QWP(-32,$key),"xmm0");	# round 0
	&$movekey	(&QWP(-16,$key),"xmm2");	# round 1
	&aeskeygenassist("xmm1","xmm2",0x01);		# round 2
	&call		(&label("key_256a_cold"));
	&aeskeygenassist("xmm1","xmm0",0x01);		# round 3
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x02);		# round 4
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x02);		# round 5
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x04);		# round 6
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x04);		# round 7
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x08);		# round 8
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x08);		# round 9
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x10);		# round 10
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x10);		# round 11
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x20);		# round 12
	&call		(&label("key_256a"));
	&aeskeygenassist("xmm1","xmm0",0x20);		# round 13
	&call		(&label("key_256b"));
	&aeskeygenassist("xmm1","xmm2",0x40);		# round 14
	&call		(&label("key_256a"));
	&$movekey	(&QWP(0,$key),"xmm0");
	&mov		(&DWP(16,$key),$rounds);
	&xor		("eax","eax");
	&ret();

&set_label("key_256a",16);
	&$movekey	(&QWP(0,$key),"xmm2");
	&lea		($key,&DWP(16,$key));
&set_label("key_256a_cold");
	&shufps		("xmm4","xmm0",0b00010000);
	&pxor		("xmm0","xmm4");
	&shufps		("xmm4","xmm0",0b10001100);
	&pxor		("xmm0","xmm4");
	&pshufd		("xmm1","xmm1",0b11111111);	# critical path
	&pxor		("xmm0","xmm1");
	&ret();

&set_label("key_256b",16);
	&$movekey	(&QWP(0,$key),"xmm0");
	&lea		($key,&DWP(16,$key));

	&shufps		("xmm4","xmm2",0b00010000);
	&pxor		("xmm2","xmm4");
	&shufps		("xmm4","xmm2",0b10001100);
	&pxor		("xmm2","xmm4");
	&pshufd		("xmm1","xmm1",0b10101010);	# critical path
	&pxor		("xmm2","xmm1");
	&ret();

&set_label("bad_pointer",4);
	&mov	("eax",-1);
	&ret	();
&set_label("bad_keybits",4);
	&mov	("eax",-2);
	&ret	();
&function_end_B("_aesni_set_encrypt_key");

# int $PREFIX_set_encrypt_key (const unsigned char *userKey, int bits,
#                              AES_KEY *key)
&function_begin_B("${PREFIX}_set_encrypt_key");
	&mov	("eax",&wparam(0));
	&mov	($rounds,&wparam(1));
	&mov	($key,&wparam(2));
	&call	("_aesni_set_encrypt_key");
	&ret	();
&function_end_B("${PREFIX}_set_encrypt_key");

# int $PREFIX_set_decrypt_key (const unsigned char *userKey, int bits,
#                              AES_KEY *key)
&function_begin_B("${PREFIX}_set_decrypt_key");
	&mov	("eax",&wparam(0));
	&mov	($rounds,&wparam(1));
	&mov	($key,&wparam(2));
	&call	("_aesni_set_encrypt_key");
	&mov	($key,&wparam(2));
	&shl	($rounds,4)	# rounds-1 after _aesni_set_encrypt_key
	&test	("eax","eax");
	&jnz	(&label("dec_key_ret"));
	&lea	("eax",&DWP(16,$key,$rounds));	# end of key schedule

	&$movekey	("xmm0",&QWP(0,$key));	# just swap
	&$movekey	("xmm1",&QWP(0,"eax"));
	&$movekey	(&QWP(0,"eax"),"xmm0");
	&$movekey	(&QWP(0,$key),"xmm1");
	&lea		($key,&DWP(16,$key));
	&lea		("eax",&DWP(-16,"eax"));

&set_label("dec_key_inverse");
	&$movekey	("xmm0",&QWP(0,$key));	# swap and inverse
	&$movekey	("xmm1",&QWP(0,"eax"));
	&aesimc		("xmm0","xmm0");
	&aesimc		("xmm1","xmm1");
	&lea		($key,&DWP(16,$key));
	&lea		("eax",&DWP(-16,"eax"));
	&cmp		("eax",$key);
	&$movekey	(&QWP(16,"eax"),"xmm0");
	&$movekey	(&QWP(-16,$key),"xmm1");
	&ja		(&label("dec_key_inverse"));

	&$movekey	("xmm0",&QWP(0,$key));	# inverse middle
	&aesimc		("xmm0","xmm0");
	&$movekey	(&QWP(0,$key),"xmm0");

	&xor		("eax","eax");		# return success
&set_label("dec_key_ret");
	&ret	();
&function_end_B("${PREFIX}_set_decrypt_key");
&asciz("AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>");

&asm_finish();
