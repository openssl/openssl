#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# SHA256 block transform for x86. September 2007.
#
# Performance improvement over compiler generated code varies from
# 10% to 40% [see below]. Not very impressive on some µ-archs, but
# it's 5 times smaller and optimizies amount of writes.
#
# May 2012.
#
# Optimization including one of Pavel Semjanov's ideas resulted in
# ~5% improvement on AMD and Sandy Bridge, and ~15% on Atom and P4.
# Pavel also suggested full unroll. While his code runs ~20%/13%/6%
# faster on K8/Core2/Sandy Bridge, it's 9.6x larger and ~14%/23%/24%
# slower on P4/Atom/Pentium...
#
# Performance in clock cycles per processed byte (less is better):
#
#		Pentium	PIII	P4	AMD K8	Core2	SB(**)	Atom
# gcc		46	36	41	27	26
# icc		57	33	38	25	23	
# x86 asm	39	31	29	19	18	19(**)	30
# x86_64 asm(*)	-	-	21	16	16	18	25
#
# (*)	x86_64 assembler performance is presented for reference
#	purposes.
# (**)	Sandy Bridge results can be improved by ~20% by replacing
#	ror with equivalent shrd.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"sha512-586.pl",$ARGV[$#ARGV] eq "386");

$A="eax";
$E="edx";
$T="ebx";
$Aoff=&DWP(4,"esp");
$Boff=&DWP(8,"esp");
$Coff=&DWP(12,"esp");
$Doff=&DWP(16,"esp");
$Eoff=&DWP(20,"esp");
$Foff=&DWP(24,"esp");
$Goff=&DWP(28,"esp");
$Hoff=&DWP(32,"esp");
$Xoff=&DWP(36,"esp");
$K256="ebp";

# *ror = sub { &shrd(@_[0],@_) };

sub BODY_00_15() {
    my $in_16_63=shift;

	&mov	("ecx",$E);
	 &mov	("esi",$Foff);
	&ror	("ecx",25-11);
	 &add	($T,"edi")			if ($in_16_63);	# T += sigma1(X[-2])
	 &mov	("edi",$Goff);
	&xor	("ecx",$E);
	 &xor	("esi","edi");
	 &mov	(&DWP(4*(9+15),"esp"),$T)	if ($in_16_63);	# save X[0]
	&ror	("ecx",11-6);
	 &and	("esi",$E);
	 &mov	($Eoff,$E);	# modulo-scheduled
	&xor	($E,"ecx");
	 &xor	("esi","edi");	# Ch(e,f,g)
	 &add	($T,$Hoff);	# T += h
	&ror	($E,6);		# Sigma1(e)
	 &mov	("ecx",$A);
	 &add	($T,"esi");	# T += Ch(e,f,g)

	&ror	("ecx",22-13);
	 &add	($T,$E);	# T += Sigma1(e)
	 &mov	("edi",$Boff);
	&xor	("ecx",$A);
	 &mov	($Aoff,$A);	# modulo-scheduled
	 &lea	("esp",&DWP(-4,"esp"));
	&ror	("ecx",13-2);
	 &mov	("esi",&DWP(0,$K256));
	&xor	("ecx",$A);
	 &mov	($E,$Eoff);	# e becomes d, which is e in next iteration
	 &xor	($A,"edi");	# a ^= b
	&ror	("ecx",2);	# Sigma0(a)

	 &add	($T,"esi");	# T+= K[i]
	 &mov	(&DWP(0,"esp"),$A);		# (b^c) in next round
	&add	($E,$T);	# d += T
	 &and	($A,&DWP(4,"esp"));	# a &= (b^c)
	&add	($T,"ecx");	# T += Sigma0(a)
	 &xor	($A,"edi");	# h = Maj(a,b,c) = Ch(a^b,c,b)

	&add	($K256,4);
	 &add	($A,$T);	# h += T
	&mov	($T,&DWP(4*(9+15+16-1),"esp"))	if ($in_16_63);	# preload T
}

&function_begin("sha256_block_data_order");
	&mov	("esi",wparam(0));	# ctx
	&mov	("edi",wparam(1));	# inp
	&mov	("eax",wparam(2));	# num
	&mov	("ebx","esp");		# saved sp

	&call	(&label("pic_point"));	# make it PIC!
&set_label("pic_point");
	&blindpop($K256);
	&lea	($K256,&DWP(&label("K256")."-".&label("pic_point"),$K256));

	&sub	("esp",16);
	&and	("esp",-64);

	&shl	("eax",6);
	&add	("eax","edi");
	&mov	(&DWP(0,"esp"),"esi");	# ctx
	&mov	(&DWP(4,"esp"),"edi");	# inp
	&mov	(&DWP(8,"esp"),"eax");	# inp+num*128
	&mov	(&DWP(12,"esp"),"ebx");	# saved sp

&set_label("loop",16);
    # copy input block to stack reversing byte and dword order
    for($i=0;$i<4;$i++) {
	&mov	("eax",&DWP($i*16+0,"edi"));
	&mov	("ebx",&DWP($i*16+4,"edi"));
	&mov	("ecx",&DWP($i*16+8,"edi"));
	&bswap	("eax");
	&mov	("edx",&DWP($i*16+12,"edi"));
	&bswap	("ebx");
	&push	("eax");
	&bswap	("ecx");
	&push	("ebx");
	&bswap	("edx");
	&push	("ecx");
	&push	("edx");
    }
	&add	("edi",64);
	&lea	("esp",&DWP(-4*9,"esp"));# place for A,B,C,D,E,F,G,H
	&mov	(&DWP(4*(9+16)+4,"esp"),"edi");

	# copy ctx->h[0-7] to A,B,C,D,E,F,G,H on stack
	&mov	($A,&DWP(0,"esi"));
	&mov	("ebx",&DWP(4,"esi"));
	&mov	("ecx",&DWP(8,"esi"));
	&mov	("edi",&DWP(12,"esi"));
	# &mov	($Aoff,$A);
	&mov	($Boff,"ebx");
	&xor	("ebx","ecx");
	&mov	($Coff,"ecx");
	&mov	($Doff,"edi");
	&mov	(&DWP(0,"esp"),"ebx");	# magic
	&mov	($E,&DWP(16,"esi"));	
	&mov	("ebx",&DWP(20,"esi"));
	&mov	("ecx",&DWP(24,"esi"));
	&mov	("edi",&DWP(28,"esi"));
	# &mov	($Eoff,$E);
	&mov	($Foff,"ebx");
	&mov	($Goff,"ecx");
	&mov	($Hoff,"edi");

&set_label("00_15",16);
	&mov	($T,&DWP(4*(9+15),"esp"));

	&BODY_00_15();

	&cmp	("esi",0xc19bf174);
	&jne	(&label("00_15"));

	&mov	($T,&DWP(4*(9+15+16-1),"esp"));	# preloaded in BODY_00_15(1)
&set_label("16_63",16);
	&mov	("esi",$T);
	 &mov	("ecx",&DWP(4*(9+15+16-14),"esp"));
	&ror	("esi",18-7);
	 &mov	("edi","ecx");
	&ror	("ecx",19-17);
	 &xor	("esi",$T);
	&shr	($T,3);
	 &xor	("ecx","edi");
	&ror	("esi",7);
	 &xor	($T,"esi");			# T = sigma0(X[-15])
	&ror	("ecx",17);
	 &add	($T,&DWP(4*(9+15+16),"esp"));	# T += X[-16]
	&shr	("edi",10);
	 &add	($T,&DWP(4*(9+15+16-9),"esp"));	# T += X[-7]
	&xor	("edi","ecx");			# sigma1(X[-2])
	# &add	($T,"edi");			# T += sigma1(X[-2])
	# &mov	(&DWP(4*(9+15),"esp"),$T);	# save X[0]

	&BODY_00_15(1);

	&cmp	("esi",0xc67178f2);
	&jne	(&label("16_63"));

	&mov	("esi",&DWP(4*(9+16+64)+0,"esp"));#ctx
	# &mov	($A,$Aoff);
	&mov	("ebx",$Boff);
	&mov	("ecx",$Coff);
	&mov	("edi",$Doff);
	&add	($A,&DWP(0,"esi"));
	&add	("ebx",&DWP(4,"esi"));
	&add	("ecx",&DWP(8,"esi"));
	&add	("edi",&DWP(12,"esi"));
	&mov	(&DWP(0,"esi"),$A);
	&mov	(&DWP(4,"esi"),"ebx");
	&mov	(&DWP(8,"esi"),"ecx");
	&mov	(&DWP(12,"esi"),"edi");
	# &mov	($E,$Eoff);
	&mov	("eax",$Foff);
	&mov	("ebx",$Goff);
	&mov	("ecx",$Hoff);
	&mov	("edi",&DWP(4*(9+16+64)+4,"esp"));#inp
	&add	($E,&DWP(16,"esi"));
	&add	("eax",&DWP(20,"esi"));
	&add	("ebx",&DWP(24,"esi"));
	&add	("ecx",&DWP(28,"esi"));
	&mov	(&DWP(16,"esi"),$E);
	&mov	(&DWP(20,"esi"),"eax");
	&mov	(&DWP(24,"esi"),"ebx");
	&mov	(&DWP(28,"esi"),"ecx");

	&lea	("esp",&DWP(4*(9+16+64),"esp"));# destroy frame
	&sub	($K256,4*64);			# rewind K

	&cmp	("edi",&DWP(8,"esp"));		# are we done yet?
	&jb	(&label("loop"));

	&mov	("esp",&DWP(12,"esp"));		# restore sp
&function_end_A();

&set_label("K256",64);	# Yes! I keep it in the code segment!
	&data_word(0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5);
	&data_word(0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5);
	&data_word(0xd807aa98,0x12835b01,0x243185be,0x550c7dc3);
	&data_word(0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174);
	&data_word(0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc);
	&data_word(0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da);
	&data_word(0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7);
	&data_word(0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967);
	&data_word(0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13);
	&data_word(0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85);
	&data_word(0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3);
	&data_word(0xd192e819,0xd6990624,0xf40e3585,0x106aa070);
	&data_word(0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5);
	&data_word(0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3);
	&data_word(0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208);
	&data_word(0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2);
&function_end_B("sha256_block_data_order");
&asciz("SHA256 block transform for x86, CRYPTOGAMS by <appro\@openssl.org>");

&asm_finish();
