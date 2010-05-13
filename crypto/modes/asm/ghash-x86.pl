#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# March 2010
#
# The module implements "4-bit" GCM GHASH function and underlying
# single multiplication operation in GF(2^128). "4-bit" means that it
# uses 256 bytes per-key table [+64/128 bytes fixed table]. It has two
# code paths: vanilla x86 and vanilla MMX. Former will be executed on
# 486 and Pentium, latter on all others. Performance results are for
# streamed GHASH subroutine and are expressed in cycles per processed
# byte, less is better:
#
#		gcc 2.95.3(*)	MMX assembler	x86 assembler
#
# Pentium	100/112(**)	-		50
# PIII		63 /77		16		24
# P4		96 /122		30		84(***)
# Opteron	50 /71		21		30
# Core2		54 /68		12.5		18
#
# (*)	gcc 3.4.x was observed to generate few percent slower code,
#	which is one of reasons why 2.95.3 results were chosen,
#	another reason is lack of 3.4.x results for older CPUs;
# (**)	second number is result for code compiled with -fPIC flag,
#	which is actually more relevant, because assembler code is
#	position-independent;
# (***)	see comment in non-MMX routine for further details;
#
# To summarize, it's >2-3 times faster than gcc-generated code. To
# anchor it to something else SHA1 assembler processes one byte in
# 11-13 cycles on contemporary x86 cores.

# May 2010
#
# Add PCLMULQDQ version performing at 2.13 cycles per processed byte.
# The question is how close is it to theoretical limit? The pclmulqdq
# instruction latency appears to be 14 cycles and there can't be more
# than 2 of them executing at any given time. This means that single
# Karatsuba multiplication would take 28 cycles *plus* few cycles for
# pre- and post-processing. Then multiplication has to be followed by
# modulo-reduction. Given that aggregated reduction method [see
# "Carry-less Multiplication and Its Usage for Computing the GCM Mode"
# white paper by Intel] allows you to perform reduction only once in
# a while we can assume that asymptotic performance can be estimated
# as (28+Tmod/Naggr)/16, where Tmod is time to perform reduction
# and Naggr is the aggregation factor.
#
# Before we proceed to this implementation let's have closer look at
# the best-performing code suggested by Intel in their white paper.
# By tracing inter-register dependencies Tmod is estimated as ~19
# cycles and Naggr is 4, resulting in 2.05 cycles per processed byte.
# As implied, this is quite optimistic estimate, because it does not
# account for Karatsuba pre- and post-processing, which for a single
# multiplication is ~5 cycles. Unfortunately Intel does not provide
# performance data for GHASH alone, only for fused GCM mode. But
# we can estimate it by subtracting CTR performance result provided
# in "AES Instruction Set" white paper: 3.54-1.38=2.16 cycles per
# processed byte or 5% off the estimate. It should be noted though
# that 3.54 is GCM result for 16KB block size, while 1.38 is CTR for
# 1KB block size, meaning that real number is likely to be a bit
# further from estimate.
#
# Moving on to the implementation in question. Tmod is estimated as
# ~13 cycles and Naggr is 2, giving asymptotic performance of ...
# 2.16. How is it possible that measured performance is better than
# optimistic theoretical estimate? There is one thing Intel failed
# to recognize. By fusing GHASH with CTR former's performance is
# really limited to above (Tmul + Tmod/Naggr) equation. But if GHASH
# procedure is detached, the modulo-reduction can be interleaved with
# Naggr-1 multiplications and under ideal conditions even disappear
# from the equation. So that optimistic theoretical estimate for this
# implementation is ... 28/16=1.75, and not 2.16. Well, it's probably
# way too optimistic, at least for such small Naggr. I'd argue that
# (28+Tproc/Naggr), where Tproc is time required for Karatsuba pre-
# and post-processing, is more realistic estimate. In this case it
# gives ... 1.91 cycles per processed byte. Or in other words,
# depending on how well we can interleave reduction and one of the
# two multiplications the performance should be betwen 1.91 and 2.16.
# As already mentioned, this implementation processes one byte [out
# of 1KB buffer] in 2.13 cycles, while x86_64 counterpart - in 2.07.
# x86_64 performance is better, because larger register bank allows
# to interleave reduction and multiplication better.
#
# Does it make sense to increase Naggr? To start with it's virtually
# impossible in 32-bit mode, because of limited register bank
# capacity. Otherwise improvement has to be weighed agiainst slower
# setup, as well as code size and complexity increase. As even
# optimistic estimate doesn't promise 30% performance improvement,
# there are currently no plans to increase Naggr.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"ghash-x86.pl",$x86only = $ARGV[$#ARGV] eq "386");

$sse2=0;
for (@ARGV) { $sse2=1 if (/-DOPENSSL_IA32_SSE2/); }

($Zhh,$Zhl,$Zlh,$Zll) = ("ebp","edx","ecx","ebx");
$inp  = "edi";
$Htbl = "esi";

$unroll = 0;	# Affects x86 loop. Folded loop performs ~7% worse
		# than unrolled, which has to be weighted against
		# 2.5x x86-specific code size reduction.

sub x86_loop {
    my $off = shift;
    my $rem = "eax";

	&mov	($Zhh,&DWP(4,$Htbl,$Zll));
	&mov	($Zhl,&DWP(0,$Htbl,$Zll));
	&mov	($Zlh,&DWP(12,$Htbl,$Zll));
	&mov	($Zll,&DWP(8,$Htbl,$Zll));
	&xor	($rem,$rem);	# avoid partial register stalls on PIII

	# shrd practically kills P4, 2.5x deterioration, but P4 has
	# MMX code-path to execute. shrd runs tad faster [than twice
	# the shifts, move's and or's] on pre-MMX Pentium (as well as
	# PIII and Core2), *but* minimizes code size, spares register
	# and thus allows to fold the loop...
	if (!$unroll) {
	my $cnt = $inp;
	&mov	($cnt,15);
	&jmp	(&label("x86_loop"));
	&set_label("x86_loop",16);
	    for($i=1;$i<=2;$i++) {
		&mov	(&LB($rem),&LB($Zll));
		&shrd	($Zll,$Zlh,4);
		&and	(&LB($rem),0xf);
		&shrd	($Zlh,$Zhl,4);
		&shrd	($Zhl,$Zhh,4);
		&shr	($Zhh,4);
		&xor	($Zhh,&DWP($off+16,"esp",$rem,4));

		&mov	(&LB($rem),&BP($off,"esp",$cnt));
		if ($i&1) {
			&and	(&LB($rem),0xf0);
		} else {
			&shl	(&LB($rem),4);
		}

		&xor	($Zll,&DWP(8,$Htbl,$rem));
		&xor	($Zlh,&DWP(12,$Htbl,$rem));
		&xor	($Zhl,&DWP(0,$Htbl,$rem));
		&xor	($Zhh,&DWP(4,$Htbl,$rem));

		if ($i&1) {
			&dec	($cnt);
			&js	(&label("x86_break"));
		} else {
			&jmp	(&label("x86_loop"));
		}
	    }
	&set_label("x86_break",16);
	} else {
	    for($i=1;$i<32;$i++) {
		&comment($i);
		&mov	(&LB($rem),&LB($Zll));
		&shrd	($Zll,$Zlh,4);
		&and	(&LB($rem),0xf);
		&shrd	($Zlh,$Zhl,4);
		&shrd	($Zhl,$Zhh,4);
		&shr	($Zhh,4);
		&xor	($Zhh,&DWP($off+16,"esp",$rem,4));

		if ($i&1) {
			&mov	(&LB($rem),&BP($off+15-($i>>1),"esp"));
			&and	(&LB($rem),0xf0);
		} else {
			&mov	(&LB($rem),&BP($off+15-($i>>1),"esp"));
			&shl	(&LB($rem),4);
		}

		&xor	($Zll,&DWP(8,$Htbl,$rem));
		&xor	($Zlh,&DWP(12,$Htbl,$rem));
		&xor	($Zhl,&DWP(0,$Htbl,$rem));
		&xor	($Zhh,&DWP(4,$Htbl,$rem));
	    }
	}
	&bswap	($Zll);
	&bswap	($Zlh);
	&bswap	($Zhl);
	if (!$x86only) {
		&bswap	($Zhh);
	} else {
		&mov	("eax",$Zhh);
		&bswap	("eax");
		&mov	($Zhh,"eax");
	}
}

if ($unroll) {
    &function_begin_B("_x86_gmult_4bit_inner");
	&x86_loop(4);
	&ret	();
    &function_end_B("_x86_gmult_4bit_inner");
}

sub deposit_rem_4bit {
    my $bias = shift;

	&mov	(&DWP($bias+0, "esp"),0x0000<<16);
	&mov	(&DWP($bias+4, "esp"),0x1C20<<16);
	&mov	(&DWP($bias+8, "esp"),0x3840<<16);
	&mov	(&DWP($bias+12,"esp"),0x2460<<16);
	&mov	(&DWP($bias+16,"esp"),0x7080<<16);
	&mov	(&DWP($bias+20,"esp"),0x6CA0<<16);
	&mov	(&DWP($bias+24,"esp"),0x48C0<<16);
	&mov	(&DWP($bias+28,"esp"),0x54E0<<16);
	&mov	(&DWP($bias+32,"esp"),0xE100<<16);
	&mov	(&DWP($bias+36,"esp"),0xFD20<<16);
	&mov	(&DWP($bias+40,"esp"),0xD940<<16);
	&mov	(&DWP($bias+44,"esp"),0xC560<<16);
	&mov	(&DWP($bias+48,"esp"),0x9180<<16);
	&mov	(&DWP($bias+52,"esp"),0x8DA0<<16);
	&mov	(&DWP($bias+56,"esp"),0xA9C0<<16);
	&mov	(&DWP($bias+60,"esp"),0xB5E0<<16);
}

$suffix = $x86only ? "" : "_x86";

&function_begin("gcm_gmult_4bit".$suffix);
	&stack_push(16+4+1);			# +1 for stack alignment
	&mov	($inp,&wparam(0));		# load Xi
	&mov	($Htbl,&wparam(1));		# load Htable

	&mov	($Zhh,&DWP(0,$inp));		# load Xi[16]
	&mov	($Zhl,&DWP(4,$inp));
	&mov	($Zlh,&DWP(8,$inp));
	&mov	($Zll,&DWP(12,$inp));

	&deposit_rem_4bit(16);

	&mov	(&DWP(0,"esp"),$Zhh);		# copy Xi[16] on stack
	&mov	(&DWP(4,"esp"),$Zhl);
	&mov	(&DWP(8,"esp"),$Zlh);
	&mov	(&DWP(12,"esp"),$Zll);
	&shr	($Zll,20);
	&and	($Zll,0xf0);

	if ($unroll) {
		&call	("_x86_gmult_4bit_inner");
	} else {
		&x86_loop(0);
		&mov	($inp,&wparam(0));
	}

	&mov	(&DWP(12,$inp),$Zll);
	&mov	(&DWP(8,$inp),$Zlh);
	&mov	(&DWP(4,$inp),$Zhl);
	&mov	(&DWP(0,$inp),$Zhh);
	&stack_pop(16+4+1);
&function_end("gcm_gmult_4bit".$suffix);

&function_begin("gcm_ghash_4bit".$suffix);
	&stack_push(16+4+1);			# +1 for 64-bit alignment
	&mov	($Zll,&wparam(0));		# load Xi
	&mov	($Htbl,&wparam(1));		# load Htable
	&mov	($inp,&wparam(2));		# load in
	&mov	("ecx",&wparam(3));		# load len
	&add	("ecx",$inp);
	&mov	(&wparam(3),"ecx");

	&mov	($Zhh,&DWP(0,$Zll));		# load Xi[16]
	&mov	($Zhl,&DWP(4,$Zll));
	&mov	($Zlh,&DWP(8,$Zll));
	&mov	($Zll,&DWP(12,$Zll));

	&deposit_rem_4bit(16);

    &set_label("x86_outer_loop",16);
	&xor	($Zll,&DWP(12,$inp));		# xor with input
	&xor	($Zlh,&DWP(8,$inp));
	&xor	($Zhl,&DWP(4,$inp));
	&xor	($Zhh,&DWP(0,$inp));
	&mov	(&DWP(12,"esp"),$Zll);		# dump it on stack
	&mov	(&DWP(8,"esp"),$Zlh);
	&mov	(&DWP(4,"esp"),$Zhl);
	&mov	(&DWP(0,"esp"),$Zhh);

	&shr	($Zll,20);
	&and	($Zll,0xf0);

	if ($unroll) {
		&call	("_x86_gmult_4bit_inner");
	} else {
		&x86_loop(0);
		&mov	($inp,&wparam(2));
	}
	&lea	($inp,&DWP(16,$inp));
	&cmp	($inp,&wparam(3));
	&mov	(&wparam(2),$inp)	if (!$unroll);
	&jb	(&label("x86_outer_loop"));

	&mov	($inp,&wparam(0));	# load Xi
	&mov	(&DWP(12,$inp),$Zll);
	&mov	(&DWP(8,$inp),$Zlh);
	&mov	(&DWP(4,$inp),$Zhl);
	&mov	(&DWP(0,$inp),$Zhh);
	&stack_pop(16+4+1);
&function_end("gcm_ghash_4bit".$suffix);

if (!$x86only) {{{

&static_label("rem_4bit");

sub mmx_loop() {
# MMX version performs 2.8 times better on P4 (see comment in non-MMX
# routine for further details), 40% better on Opteron and Core2, 50%
# better on PIII... In other words effort is considered to be well
# spent...
    my $inp = shift;
    my $rem_4bit = shift;
    my $cnt = $Zhh;
    my $nhi = $Zhl;
    my $nlo = $Zlh;
    my $rem = $Zll;

    my ($Zlo,$Zhi) = ("mm0","mm1");
    my $tmp = "mm2";

	&xor	($nlo,$nlo);	# avoid partial register stalls on PIII
	&mov	($nhi,$Zll);
	&mov	(&LB($nlo),&LB($nhi));
	&mov	($cnt,14);
	&shl	(&LB($nlo),4);
	&and	($nhi,0xf0);
	&movq	($Zlo,&QWP(8,$Htbl,$nlo));
	&movq	($Zhi,&QWP(0,$Htbl,$nlo));
	&movd	($rem,$Zlo);
	&jmp	(&label("mmx_loop"));

    &set_label("mmx_loop",16);
	&psrlq	($Zlo,4);
	&and	($rem,0xf);
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&pxor	($Zlo,&QWP(8,$Htbl,$nhi));
	&mov	(&LB($nlo),&BP(0,$inp,$cnt));
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
	&dec	($cnt);
	&movd	($rem,$Zlo);
	&pxor	($Zhi,&QWP(0,$Htbl,$nhi));
	&mov	($nhi,$nlo);
	&pxor	($Zlo,$tmp);
	&js	(&label("mmx_break"));

	&shl	(&LB($nlo),4);
	&and	($rem,0xf);
	&psrlq	($Zlo,4);
	&and	($nhi,0xf0);
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&pxor	($Zlo,&QWP(8,$Htbl,$nlo));
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
	&movd	($rem,$Zlo);
	&pxor	($Zhi,&QWP(0,$Htbl,$nlo));
	&pxor	($Zlo,$tmp);
	&jmp	(&label("mmx_loop"));

    &set_label("mmx_break",16);
	&shl	(&LB($nlo),4);
	&and	($rem,0xf);
	&psrlq	($Zlo,4);
	&and	($nhi,0xf0);
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&pxor	($Zlo,&QWP(8,$Htbl,$nlo));
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
	&movd	($rem,$Zlo);
	&pxor	($Zhi,&QWP(0,$Htbl,$nlo));
	&pxor	($Zlo,$tmp);

	&psrlq	($Zlo,4);
	&and	($rem,0xf);
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&pxor	($Zlo,&QWP(8,$Htbl,$nhi));
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
	&movd	($rem,$Zlo);
	&pxor	($Zhi,&QWP(0,$Htbl,$nhi));
	&pxor	($Zlo,$tmp);

	&psrlq	($Zlo,32);	# lower part of Zlo is already there
	&movd	($Zhl,$Zhi);
	&psrlq	($Zhi,32);
	&movd	($Zlh,$Zlo);
	&movd	($Zhh,$Zhi);

	&bswap	($Zll);
	&bswap	($Zhl);
	&bswap	($Zlh);
	&bswap	($Zhh);
}

&function_begin("gcm_gmult_4bit_mmx");
	&mov	($inp,&wparam(0));	# load Xi
	&mov	($Htbl,&wparam(1));	# load Htable

	&call	(&label("pic_point"));
	&set_label("pic_point");
	&blindpop("eax");
	&lea	("eax",&DWP(&label("rem_4bit")."-".&label("pic_point"),"eax"));

	&movz	($Zll,&BP(15,$inp));

	&mmx_loop($inp,"eax");

	&emms	();
	&mov	(&DWP(12,$inp),$Zll);
	&mov	(&DWP(4,$inp),$Zhl);
	&mov	(&DWP(8,$inp),$Zlh);
	&mov	(&DWP(0,$inp),$Zhh);
&function_end("gcm_gmult_4bit_mmx");

# Streamed version performs 20% better on P4, 7% on Opteron,
# 10% on Core2 and PIII...
&function_begin("gcm_ghash_4bit_mmx");
	&mov	($Zhh,&wparam(0));	# load Xi
	&mov	($Htbl,&wparam(1));	# load Htable
	&mov	($inp,&wparam(2));	# load in
	&mov	($Zlh,&wparam(3));	# load len

	&call	(&label("pic_point"));
	&set_label("pic_point");
	&blindpop("eax");
	&lea	("eax",&DWP(&label("rem_4bit")."-".&label("pic_point"),"eax"));

	&add	($Zlh,$inp);
	&mov	(&wparam(3),$Zlh);	# len to point at the end of input
	&stack_push(4+1);		# +1 for stack alignment

	&mov	($Zll,&DWP(12,$Zhh));	# load Xi[16]
	&mov	($Zhl,&DWP(4,$Zhh));
	&mov	($Zlh,&DWP(8,$Zhh));
	&mov	($Zhh,&DWP(0,$Zhh));
	&jmp	(&label("mmx_outer_loop"));

    &set_label("mmx_outer_loop",16);
	&xor	($Zll,&DWP(12,$inp));
	&xor	($Zhl,&DWP(4,$inp));
	&xor	($Zlh,&DWP(8,$inp));
	&xor	($Zhh,&DWP(0,$inp));
	&mov	(&DWP(12,"esp"),$Zll);
	&mov	(&DWP(4,"esp"),$Zhl);
	&mov	(&DWP(8,"esp"),$Zlh);
	&mov	(&DWP(0,"esp"),$Zhh);

	&shr	($Zll,24);

	&mmx_loop("esp","eax");

	&lea	($inp,&DWP(16,$inp));
	&cmp	($inp,&wparam(3));
	&jb	(&label("mmx_outer_loop"));

	&mov	($inp,&wparam(0));	# load Xi
	&emms	();
	&mov	(&DWP(12,$inp),$Zll);
	&mov	(&DWP(4,$inp),$Zhl);
	&mov	(&DWP(8,$inp),$Zlh);
	&mov	(&DWP(0,$inp),$Zhh);

	&stack_pop(4+1);
&function_end("gcm_ghash_4bit_mmx");

if ($sse2) {{
######################################################################
# PCLMULQDQ version.

$Xip="eax";
$Htbl="edx";
$const="ecx";
$inp="esi";
$len="ebx";

($Xi,$Xhi)=("xmm0","xmm1");	$Hkey="xmm2";
($T1,$T2,$T3)=("xmm3","xmm4","xmm5");
($Xn,$Xhn)=("xmm6","xmm7");

&static_label("bswap");

sub clmul64x64_T2 {	# minimal "register" pressure
my ($Xhi,$Xi,$Hkey)=@_;

	&movdqa		($Xhi,$Xi);		#
	&pshufd		($T1,$Xi,0b01001110);
	&pshufd		($T2,$Hkey,0b01001110);
	&pxor		($T1,$Xi);		#
	&pxor		($T2,$Hkey);

	&pclmulqdq	($Xi,$Hkey,0x00);	#######
	&pclmulqdq	($Xhi,$Hkey,0x11);	#######
	&pclmulqdq	($T1,$T2,0x00);		#######
	&pxor		($T1,$Xi);		#
	&pxor		($T1,$Xhi);		#

	&movdqa		($T2,$T1);		#
	&psrldq		($T1,8);
	&pslldq		($T2,8);		#
	&pxor		($Xhi,$T1);
	&pxor		($Xi,$T2);		#
}

sub clmul64x64_T3 {
# Even though this subroutine offers visually better ILP, it
# was empirically found to be a tad slower than above version.
# At least in gcm_ghash_clmul context. But it's just as well,
# because loop modulo-scheduling is possible only thanks to
# minimized "register" pressure...
my ($Xhi,$Xi,$Hkey)=@_;

	&movdqa		($T1,$Xi);		#
	&movdqa		($Xhi,$Xi);
	&pclmulqdq	($Xi,$Hkey,0x00);	#######
	&pclmulqdq	($Xhi,$Hkey,0x11);	#######
	&pshufd		($T2,$T1,0b01001110);	#
	&pshufd		($T3,$Hkey,0b01001110);
	&pxor		($T2,$T1);		#
	&pxor		($T3,$Hkey);
	&pclmulqdq	($T2,$T3,0x00);		#######
	&pxor		($T2,$Xi);		#
	&pxor		($T2,$Xhi);		#

	&movdqa		($T3,$T2);		#
	&psrldq		($T2,8);
	&pslldq		($T3,8);		#
	&pxor		($Xhi,$T2);
	&pxor		($Xi,$T3);		#
}

if (1) {		# Algorithm 9 with <<1 twist.
			# Reduction is shorter and uses only two
			# temporary registers, which makes it better
			# candidate for interleaving with 64x64
			# multiplication. Pre-modulo-scheduled loop
			# was found to be ~20% faster than Algorithm 5
			# below. Algorithm 9 was then chosen and
			# optimized further...

sub reduction_alg9 {	# 17/13 times faster than Intel version
my ($Xhi,$Xi) = @_;

	# 1st phase
	&movdqa		($T1,$Xi)		#
	&psllq		($Xi,1);
	&pxor		($Xi,$T1);		#
	&psllq		($Xi,5);		#
	&pxor		($Xi,$T1);		#
	&psllq		($Xi,57);		#
	&movdqa		($T2,$Xi);		#
	&pslldq		($Xi,8);
	&psrldq		($T2,8);		#	
	&pxor		($Xi,$T1);
	&pxor		($Xhi,$T2);		#

	# 2nd phase
	&movdqa		($T2,$Xi);
	&psrlq		($Xi,5);
	&pxor		($Xi,$T2);		#
	&psrlq		($Xi,1);		#
	&pxor		($Xi,$T2);		#
	&pxor		($T2,$Xhi);
	&psrlq		($Xi,1);		#
	&pxor		($Xi,$T2);		#
}

&function_begin_B("gcm_init_clmul");
	&mov		($Htbl,&wparam(0));
	&mov		($Xip,&wparam(1));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Hkey,&QWP(0,$Xip));
	&pshufd		($Hkey,$Hkey,0b01001110);# dword swap

	# <<1 twist
	&pshufd		($T2,$Hkey,0b11111111);	# broadcast uppermost dword
	&movdqa		($T1,$Hkey);
	&psllq		($Hkey,1);
	&pxor		($T3,$T3);		#
	&psrlq		($T1,63);
	&pcmpgtd	($T3,$T2);		# broadcast carry bit
	&pslldq		($T1,8);
	&por		($Hkey,$T1);		# H<<=1

	# magic reduction
	&pand		($T3,&QWP(16,$const));	# 0x1c2_polynomial
	&pxor		($Hkey,$T3);		# if(carry) H^=0x1c2_polynomial

	# calculate H^2
	&movdqa		($Xi,$Hkey);
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);
	&reduction_alg9	($Xhi,$Xi);

	&movdqu		(&QWP(0,$Htbl),$Hkey);	# save H
	&movdqu		(&QWP(16,$Htbl),$Xi);	# save H^2

	&ret		();
&function_end_B("gcm_init_clmul");

&function_begin_B("gcm_gmult_clmul");
	&mov		($Xip,&wparam(0));
	&mov		($Htbl,&wparam(1));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Xi,&QWP(0,$Xip));
	&movdqa		($T3,&QWP(0,$const));
	&movdqu		($Hkey,&QWP(0,$Htbl));
	&pshufb		($Xi,$T3);

	&clmul64x64_T2	($Xhi,$Xi,$Hkey);
	&reduction_alg9	($Xhi,$Xi);

	&pshufb		($Xi,$T3);
	&movdqu		(&QWP(0,$Xip),$Xi);

	&ret	();
&function_end_B("gcm_gmult_clmul");

&function_begin("gcm_ghash_clmul");
	&mov		($Xip,&wparam(0));
	&mov		($Htbl,&wparam(1));
	&mov		($inp,&wparam(2));
	&mov		($len,&wparam(3));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Xi,&QWP(0,$Xip));
	&movdqa		($T3,&QWP(0,$const));
	&movdqu		($Hkey,&QWP(0,$Htbl));
	&pshufb		($Xi,$T3);

	&sub		($len,0x10);
	&jz		(&label("odd_tail"));

	#######
	# Xi+2 =[H*(Ii+1 + Xi+1)] mod P =
	#	[(H*Ii+1) + (H*Xi+1)] mod P =
	#	[(H*Ii+1) + H^2*(Ii+Xi)] mod P
	#
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&movdqu		($Xn,&QWP(16,$inp));	# Ii+1
	&pshufb		($T1,$T3);
	&pshufb		($Xn,$T3);
	&pxor		($Xi,$T1);		# Ii+Xi

	&clmul64x64_T2	($Xhn,$Xn,$Hkey);	# H*Ii+1
	&movdqu		($Hkey,&QWP(16,$Htbl));	# load H^2

	&lea		($inp,&DWP(32,$inp));	# i+=2
	&sub		($len,0x20);
	&jbe		(&label("even_tail"));

&set_label("mod_loop");
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);	# H^2*(Ii+Xi)
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&movdqu		($Hkey,&QWP(0,$Htbl));	# load H

	&pxor		($Xi,$Xn);		# (H*Ii+1) + H^2*(Ii+Xi)
	&pxor		($Xhi,$Xhn);

	&movdqu		($Xn,&QWP(16,$inp));	# Ii+1
	&pshufb		($T1,$T3);
	&pshufb		($Xn,$T3);

	&movdqa		($T3,$Xn);		#&clmul64x64_TX	($Xhn,$Xn,$Hkey); H*Ii+1
	&movdqa		($Xhn,$Xn);
	 &pxor		($Xhi,$T1);		# "Ii+Xi", consume early

	  &movdqa	($T1,$Xi)		#&reduction_alg9($Xhi,$Xi); 1st phase
	  &psllq	($Xi,1);
	  &pxor		($Xi,$T1);		#
	  &psllq	($Xi,5);		#
	  &pxor		($Xi,$T1);		#
	&pclmulqdq	($Xn,$Hkey,0x00);	#######
	  &psllq	($Xi,57);		#
	  &movdqa	($T2,$Xi);		#
	  &pslldq	($Xi,8);
	  &psrldq	($T2,8);		#	
	  &pxor		($Xi,$T1);
	&pshufd		($T1,$T3,0b01001110);
	  &pxor		($Xhi,$T2);		#
	&pxor		($T1,$T3);
	&pshufd		($T3,$Hkey,0b01001110);
	&pxor		($T3,$Hkey);		#

	&pclmulqdq	($Xhn,$Hkey,0x11);	#######
	  &movdqa	($T2,$Xi);		# 2nd phase
	  &psrlq	($Xi,5);
	  &pxor		($Xi,$T2);		#
	  &psrlq	($Xi,1);		#
	  &pxor		($Xi,$T2);		#
	  &pxor		($T2,$Xhi);
	  &psrlq	($Xi,1);		#
	  &pxor		($Xi,$T2);		#

	&pclmulqdq	($T1,$T3,0x00);		#######
	&movdqu		($Hkey,&QWP(16,$Htbl));	# load H^2
	&pxor		($T1,$Xn);		#
	&pxor		($T1,$Xhn);		#

	&movdqa		($T3,$T1);		#
	&psrldq		($T1,8);
	&pslldq		($T3,8);		#
	&pxor		($Xhn,$T1);
	&pxor		($Xn,$T3);		#
	&movdqa		($T3,&QWP(0,$const));

	&lea		($inp,&DWP(32,$inp));
	&sub		($len,0x20);
	&ja		(&label("mod_loop"));

&set_label("even_tail");
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);	# H^2*(Ii+Xi)

	&pxor		($Xi,$Xn);		# (H*Ii+1) + H^2*(Ii+Xi)
	&pxor		($Xhi,$Xhn);

	&reduction_alg9	($Xhi,$Xi);

	&test		($len,$len);
	&jnz		(&label("done"));

	&movdqu		($Hkey,&QWP(0,$Htbl));	# load H
&set_label("odd_tail");
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&pshufb		($T1,$T3);
	&pxor		($Xi,$T1);		# Ii+Xi

	&clmul64x64_T2	($Xhi,$Xi,$Hkey);	# H*(Ii+Xi)
	&reduction_alg9	($Xhi,$Xi);

&set_label("done");
	&pshufb		($Xi,$T3);
	&movdqu		(&QWP(0,$Xip),$Xi);
&function_end("gcm_ghash_clmul");

} else {		# Algorith 5. Kept for reference purposes.

sub reduction_alg5 {	# 19/16 times faster than Intel version
my ($Xhi,$Xi)=@_;

	# <<1
	&movdqa		($T1,$Xi);		#
	&movdqa		($T2,$Xhi);
	&pslld		($Xi,1);
	&pslld		($Xhi,1);		#
	&psrld		($T1,31);
	&psrld		($T2,31);		#
	&movdqa		($T3,$T1);
	&pslldq		($T1,4);
	&psrldq		($T3,12);		#
	&pslldq		($T2,4);
	&por		($Xhi,$T3);		#
	&por		($Xi,$T1);
	&por		($Xhi,$T2);		#

	# 1st phase
	&movdqa		($T1,$Xi);
	&movdqa		($T2,$Xi);
	&movdqa		($T3,$Xi);		#
	&pslld		($T1,31);
	&pslld		($T2,30);
	&pslld		($Xi,25);		#
	&pxor		($T1,$T2);
	&pxor		($T1,$Xi);		#
	&movdqa		($T2,$T1);		#
	&pslldq		($T1,12);
	&psrldq		($T2,4);		#
	&pxor		($T3,$T1);

	# 2nd phase
	&pxor		($Xhi,$T3);		#
	&movdqa		($Xi,$T3);
	&movdqa		($T1,$T3);
	&psrld		($Xi,1);		#
	&psrld		($T1,2);
	&psrld		($T3,7);		#
	&pxor		($Xi,$T1);
	&pxor		($Xhi,$T2);
	&pxor		($Xi,$T3);		#
	&pxor		($Xi,$Xhi);		#
}

&function_begin_B("gcm_init_clmul");
	&mov		($Htbl,&wparam(0));
	&mov		($Xip,&wparam(1));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Hkey,&QWP(0,$Xip));
	&pshufd		($Hkey,$Hkey,0b01001110);# dword swap

	# calculate H^2
	&movdqa		($Xi,$Hkey);
	&clmul64x64_T3	($Xhi,$Xi,$Hkey);
	&reduction_alg5	($Xhi,$Xi);

	&movdqu		(&QWP(0,$Htbl),$Hkey);	# save H
	&movdqu		(&QWP(16,$Htbl),$Xi);	# save H^2

	&ret		();
&function_end_B("gcm_init_clmul");

&function_begin_B("gcm_gmult_clmul");
	&mov		($Xip,&wparam(0));
	&mov		($Htbl,&wparam(1));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Xi,&QWP(0,$Xip));
	&movdqa		($Xn,&QWP(0,$const));
	&movdqu		($Hkey,&QWP(0,$Htbl));
	&pshufb		($Xi,$Xn);

	&clmul64x64_T3	($Xhi,$Xi,$Hkey);
	&reduction_alg5	($Xhi,$Xi);

	&pshufb		($Xi,$Xn);
	&movdqu		(&QWP(0,$Xip),$Xi);

	&ret	();
&function_end_B("gcm_gmult_clmul");

&function_begin("gcm_ghash_clmul");
	&mov		($Xip,&wparam(0));
	&mov		($Htbl,&wparam(1));
	&mov		($inp,&wparam(2));
	&mov		($len,&wparam(3));

	&call		(&label("pic"));
&set_label("pic");
	&blindpop	($const);
	&lea		($const,&DWP(&label("bswap")."-".&label("pic"),$const));

	&movdqu		($Xi,&QWP(0,$Xip));
	&movdqa		($T3,&QWP(0,$const));
	&movdqu		($Hkey,&QWP(0,$Htbl));
	&pshufb		($Xi,$T3);

	&sub		($len,0x10);
	&jz		(&label("odd_tail"));

	#######
	# Xi+2 =[H*(Ii+1 + Xi+1)] mod P =
	#	[(H*Ii+1) + (H*Xi+1)] mod P =
	#	[(H*Ii+1) + H^2*(Ii+Xi)] mod P
	#
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&movdqu		($Xn,&QWP(16,$inp));	# Ii+1
	&pshufb		($T1,$T3);
	&pshufb		($Xn,$T3);
	&pxor		($Xi,$T1);		# Ii+Xi

	&clmul64x64_T3	($Xhn,$Xn,$Hkey);	# H*Ii+1
	&movdqu		($Hkey,&QWP(16,$Htbl));	# load H^2

	&sub		($len,0x20);
	&lea		($inp,&DWP(32,$inp));	# i+=2
	&jbe		(&label("even_tail"));

&set_label("mod_loop");
	&clmul64x64_T3	($Xhi,$Xi,$Hkey);	# H^2*(Ii+Xi)
	&movdqu		($Hkey,&QWP(0,$Htbl));	# load H

	&pxor		($Xi,$Xn);		# (H*Ii+1) + H^2*(Ii+Xi)
	&pxor		($Xhi,$Xhn);

	&reduction_alg5	($Xhi,$Xi);

	#######
	&movdqa		($T3,&QWP(0,$const));
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&movdqu		($Xn,&QWP(16,$inp));	# Ii+1
	&pshufb		($T1,$T3);
	&pshufb		($Xn,$T3);
	&pxor		($Xi,$T1);		# Ii+Xi

	&clmul64x64_T3	($Xhn,$Xn,$Hkey);	# H*Ii+1
	&movdqu		($Hkey,&QWP(16,$Htbl));	# load H^2

	&sub		($len,0x20);
	&lea		($inp,&DWP(32,$inp));
	&ja		(&label("mod_loop"));

&set_label("even_tail");
	&clmul64x64_T3	($Xhi,$Xi,$Hkey);	# H^2*(Ii+Xi)

	&pxor		($Xi,$Xn);		# (H*Ii+1) + H^2*(Ii+Xi)
	&pxor		($Xhi,$Xhn);

	&reduction_alg5	($Xhi,$Xi);

	&movdqa		($T3,&QWP(0,$const));
	&test		($len,$len);
	&jnz		(&label("done"));

	&movdqu		($Hkey,&QWP(0,$Htbl));	# load H
&set_label("odd_tail");
	&movdqu		($T1,&QWP(0,$inp));	# Ii
	&pshufb		($T1,$T3);
	&pxor		($Xi,$T1);		# Ii+Xi

	&clmul64x64_T3	($Xhi,$Xi,$Hkey);	# H*(Ii+Xi)
	&reduction_alg5	($Xhi,$Xi);

	&movdqa		($T3,&QWP(0,$const));
&set_label("done");
	&pshufb		($Xi,$T3);
	&movdqu		(&QWP(0,$Xip),$Xi);
&function_end("gcm_ghash_clmul");

}

&set_label("bswap",64);
	&data_byte(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
	&data_byte(1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xc2);	# 0x1c2_polynomial
}}	# $sse2

&set_label("rem_4bit",64);
	&data_word(0,0x0000<<16,0,0x1C20<<16,0,0x3840<<16,0,0x2460<<16);
	&data_word(0,0x7080<<16,0,0x6CA0<<16,0,0x48C0<<16,0,0x54E0<<16);
	&data_word(0,0xE100<<16,0,0xFD20<<16,0,0xD940<<16,0,0xC560<<16);
	&data_word(0,0x9180<<16,0,0x8DA0<<16,0,0xA9C0<<16,0,0xB5E0<<16);
}}}	# !$x86only

&asciz("GHASH for x86, CRYPTOGAMS by <appro\@openssl.org>");
&asm_finish();
