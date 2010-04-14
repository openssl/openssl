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
# Core2		54 /68		13		18
#
# (*)	gcc 3.4.x was observed to generate few percent slower code,
#	which is one of reasons why 2.95.3 results were chosen,
#	another reason is lack of 3.4.x results for older CPUs;
# (**)	second number is result for code compiled with -fPIC flag,
#	which is actually more relevant, because assembler code is
#	position-independent;
# (***)	see comment in non-MMX routine for further details;
#
# To summarize, it's 2-3 times faster than gcc-generated code. To
# anchor it to something else SHA1 assembler processes one byte in
# 11-13 cycles on contemporary x86 cores.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"gcm-x86.pl",$x86only = $ARGV[$#ARGV] eq "386");

&static_label("rem_4bit") if (!$x86only);

$Zhh  = "ebp";
$Zhl  = "edx";
$Zlh  = "ecx";
$Zll  = "ebx";
$inp  = "edi";
$Htbl = "esi";

$unroll = 0;	# Affects x86 loop. Folded loop performs ~7% worse
		# than unrolled, which has to be weighted against
		# 1.7x code size reduction. Well, *overall* 1.7x,
		# x86-specific code itself shrinks by 2.5x...

sub mmx_loop() {
# MMX version performs 2.8 times better on P4 (see comment in non-MMX
# routine for further details), 40% better on Opteron, 50% better
# on PIII and Core2... In other words effort is considered to be well
# spent...
    my $inp = shift;
    my $rem_4bit = shift;
    my $cnt = $Zhh;
    my $nhi = $Zhl;
    my $nlo = $Zlh;
    my $rem = $Zll;

    my $Zlo = "mm0";
    my $Zhi = "mm1";
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
	&pxor	($Zlo,&QWP(8,$Htbl,$nhi));
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&mov	(&LB($nlo),&BP(0,$inp,$cnt));
	&dec	($cnt);
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
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
	&pxor	($Zlo,&QWP(8,$Htbl,$nhi));
	&movq	($tmp,$Zhi);
	&psrlq	($Zhi,4);
	&psllq	($tmp,60);
	&pxor	($Zhi,&QWP(0,$rem_4bit,$rem,8));
	&movd	($rem,$Zlo);
	&pxor	($Zhi,&QWP(0,$Htbl,$nhi));
	&mov	($nhi,$nlo);
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

&function_begin("gcm_gmult_4bit");
    if (!$x86only) {
	&call	(&label("pic_point"));
	&set_label("pic_point");
	&blindpop("eax");
	&picmeup("ebp","OPENSSL_ia32cap_P","eax",&label("pic_point"));
	&bt	(&DWP(0,"ebp"),23);	# check for MMX bit
	&jnc	(&label("x86"));

	&lea	("eax",&DWP(&label("rem_4bit")."-".&label("pic_point"),"eax"));

	&mov	($inp,&wparam(0));	# load Xi
	&mov	($Htbl,&wparam(1));	# load Htable

	&movz	($Zll,&BP(15,$inp));

	&mmx_loop($inp,"eax");

	&emms	();
	&mov	(&DWP(12,$inp),$Zll);
	&mov	(&DWP(4,$inp),$Zhl);
	&mov	(&DWP(8,$inp),$Zlh);
	&mov	(&DWP(0,$inp),$Zhh);

	&function_end_A();
    &set_label("x86",16);
    }
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
&function_end("gcm_gmult_4bit");

# Streamed version performs 20% better on P4, 7% on Opteron,
# 10% on Core2 and PIII...
&function_begin("gcm_ghash_4bit");
    if (!$x86only) {
	&call	(&label("pic_point"));
	&set_label("pic_point");
	&blindpop("eax");
	&picmeup("ebp","OPENSSL_ia32cap_P","eax",&label("pic_point"));
	&bt	(&DWP(0,"ebp"),23);	# check for MMX bit
	&jnc	(&label("x86"));

	&lea	("eax",&DWP(&label("rem_4bit")."-".&label("pic_point"),"eax"));

	&mov	($Zhh,&wparam(0));	# load Xi
	&mov	($Htbl,&wparam(1));	# load Htable
	&mov	($inp,&wparam(2));	# load in
	&mov	($Zlh,&wparam(3));	# load len
	&add	($Zlh,$inp);
	&mov	(&wparam(3),$Zlh);	# len to point at the end of input
	&stack_push(4+1);		# +1 for stack alignment
	&mov	($Zll,&DWP(12,$Zhh));	# load Xi[16]
	&mov	($Zhl,&DWP(4,$Zhh));
	&mov	($Zlh,&DWP(8,$Zhh));
	&mov	($Zhh,&DWP(0,$Zhh));

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
	&function_end_A();
    &set_label("x86",16);
    }
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
&function_end("gcm_ghash_4bit");

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

if (!$x86only) {
&set_label("rem_4bit",64);
	&data_word(0,0x0000<<16,0,0x1C20<<16,0,0x3840<<16,0,0x2460<<16);
	&data_word(0,0x7080<<16,0,0x6CA0<<16,0,0x48C0<<16,0,0x54E0<<16);
	&data_word(0,0xE100<<16,0,0xFD20<<16,0,0xD940<<16,0,0xC560<<16);
	&data_word(0,0x9180<<16,0,0x8DA0<<16,0,0xA9C0<<16,0,0xB5E0<<16);
}
&asciz("GHASH for x86, CRYPTOGAMS by <appro\@openssl.org>");
&asm_finish();
