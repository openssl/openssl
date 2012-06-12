#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
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
# Optimization including two of Pavel Semjanov's ideas, alternative
# Maj and full unroll, resulted in ~20-25% improvement on most CPUs,
# ~7% on Pentium, ~40% on Atom. As fully unrolled loop body is almost
# 15x larger, 8KB vs. 560B, it's fired only for longer inputs. But not
# on P4, where it kills performance, nor Sandy Bridge, where folded
# loop is approximately as fast...
#
# Performance in clock cycles per processed byte (less is better):
#
#		PIII	P4	AMD K8	Core2	SB(**)	Atom	Bldzr
# gcc		36	41	27	26	25	50	36
# icc		33	38	25	23	-	-	-
# x86 asm(*)	27/24	28	19/15.5	18/15.6	16(**)	30/25	27/22
# x86_64 asm(***)	17.5	15	15.5	17.5	23	21
#
# (*)	numbers after slash are for unrolled loop, where available;
# (**)	for Sandy Bridge executing code path with ror replaced with
#	equivalent shrd;
# (***)	x86_64 assembly performance is presented for reference
#	purposes.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"sha512-586.pl",$ARGV[$#ARGV] eq "386");

$unroll_after = 64*4;	# If pre-evicted from L1P cache first spin of
			# fully unrolled loop was measured to run about
			# 3-4x slower. If slowdown coefficient is N and
			# unrolled loop is m times faster, then you break
			# even at (N-1)/(m-1) blocks. Then it needs to be
			# adjusted for probability of code being evicted,
			# code size/cache size=1/4. Typical m is 1.15...

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

sub BODY_16_63() {
	&mov	($T,"ecx");			# "ecx" is preloaded
	 &mov	("esi",&DWP(4*(9+15+16-14),"esp"));
	&ror	("ecx",18-7);
	 &mov	("edi","esi");
	&ror	("esi",19-17);
	 &xor	("ecx",$T);
	 &shr	($T,3);
	&ror	("ecx",7);
	 &xor	("esi","edi");
	 &xor	($T,"ecx");			# T = sigma0(X[-15])
	&ror	("esi",17);
	 &add	($T,&DWP(4*(9+15+16),"esp"));	# T += X[-16]
	&shr	("edi",10);
	 &add	($T,&DWP(4*(9+15+16-9),"esp"));	# T += X[-7]
	#&xor	("edi","esi")			# sigma1(X[-2])
	# &add	($T,"edi");			# T += sigma1(X[-2])
	# &mov	(&DWP(4*(9+15),"esp"),$T);	# save X[0]

	&BODY_00_15(1);
}
sub BODY_00_15() {
    my $in_16_63=shift;

	&mov	("ecx",$E);
	 &xor	("edi","esi")			if ($in_16_63);	# sigma1(X[-2])
	 &mov	("esi",$Foff);
	&ror	("ecx",25-11);
	 &add	($T,"edi")			if ($in_16_63);	# T += sigma1(X[-2])
	 &mov	("edi",$Goff);
	&xor	("ecx",$E);
	 &xor	("esi","edi");
	 &mov	($T,&DWP(4*(9+15),"esp"))	if (!$in_16_63);
	 &mov	(&DWP(4*(9+15),"esp"),$T)	if ($in_16_63);	# save X[0]
	&ror	("ecx",11-6);
	 &and	("esi",$E);
	 &mov	($Eoff,$E);		# modulo-scheduled
	&xor	($E,"ecx");
	 &add	($T,$Hoff);		# T += h
	 &xor	("esi","edi");		# Ch(e,f,g)
	&ror	($E,6);			# Sigma1(e)
	 &mov	("ecx",$A);
	 &add	($T,"esi");		# T += Ch(e,f,g)

	&ror	("ecx",22-13);
	 &add	($T,$E);		# T += Sigma1(e)
	 &mov	("edi",$Boff);
	&xor	("ecx",$A);
	 &mov	($Aoff,$A);		# modulo-scheduled
	 &lea	("esp",&DWP(-4,"esp"));
	&ror	("ecx",13-2);
	 &mov	("esi",&DWP(0,$K256));
	&xor	("ecx",$A);
	 &mov	($E,$Eoff);		# e in next iteration, d in this one
	 &xor	($A,"edi");		# a ^= b
	&ror	("ecx",2);		# Sigma0(a)

	 &add	($T,"esi");		# T+= K[i]
	 &mov	(&DWP(0,"esp"),$A);	# (b^c) in next round
	&add	($E,$T);		# d += T
	 &and	($A,&DWP(4,"esp"));	# a &= (b^c)
	&add	($T,"ecx");		# T += Sigma0(a)
	 &xor	($A,"edi");		# h = Maj(a,b,c) = Ch(a^b,c,b)
	 &mov	("ecx",&DWP(4*(9+15+16-1),"esp"))	if ($in_16_63);	# preload T
	&add	($K256,4);
	 &add	($A,$T);		# h += T
}

&external_label("OPENSSL_ia32cap_P")		if (!$i386);

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
						if (!$i386) {
	&picmeup("edx","OPENSSL_ia32cap_P",$K256,&label("K256"));
	&mov	("ecx",&DWP(0,"edx"));
	&mov	("edx",&DWP(4,"edx"));
	&test	("ecx",1<<20);		# check for P4
	&jnz	(&label("loop"));
	&and	("ecx",1<<30);		# mask "Intel CPU" bit
	&and	("edx",1<<28);		# mask AVX bit
	&or	("ecx","edx");
	&cmp	("ecx",1<<28|1<<30);
	&je	(&label("loop_shrd"));
						if ($unroll_after) {
	&sub	("eax","edi");
	&cmp	("eax",$unroll_after);
	&jae	(&label("unrolled"));
						} }
	&jmp	(&label("loop"));

sub COMPACT_LOOP() {
my $suffix=shift;

&set_label("loop$suffix",16);
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

&set_label("00_15$suffix",16);

	&BODY_00_15();

	&cmp	("esi",0xc19bf174);
	&jne	(&label("00_15$suffix"));

	&mov	("ecx",&DWP(4*(9+15+16-1),"esp"));	# preloaded in BODY_00_15(1)
	&jmp	(&label("16_63$suffix"));

&set_label("16_63$suffix",16);

	&BODY_16_63();

	&cmp	("esi",0xc67178f2);
	&jne	(&label("16_63$suffix"));

	&mov	("esi",&DWP(4*(9+16+64)+0,"esp"));#ctx
	# &mov	($A,$Aoff);
	&mov	("ebx",$Boff);
	# &mov	("edi",$Coff);
	&mov	("ecx",$Doff);
	&add	($A,&DWP(0,"esi"));
	&add	("ebx",&DWP(4,"esi"));
	&add	("edi",&DWP(8,"esi"));
	&add	("ecx",&DWP(12,"esi"));
	&mov	(&DWP(0,"esi"),$A);
	&mov	(&DWP(4,"esi"),"ebx");
	&mov	(&DWP(8,"esi"),"edi");
	&mov	(&DWP(12,"esi"),"ecx");
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
	&jb	(&label("loop$suffix"));
}
	&COMPACT_LOOP();
	&mov	("esp",&DWP(12,"esp"));		# restore sp
&function_end_A();
						if (!$i386) {
	# ~20% improvement on Sandy Bridge
	local *ror = sub { &shrd(@_[0],@_) };
	&COMPACT_LOOP("_shrd");
	&mov	("esp",&DWP(12,"esp"));		# restore sp
&function_end_A();
						}

&set_label("K256",64);	# Yes! I keep it in the code segment!
@K256=(	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2	);
&data_word(@K256);
&data_word(0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f);

if (!$i386 && $unroll_after) {
my @AH=($A,$K256);

&set_label("unrolled",16);
	&lea	("esp",&DWP(-96,"esp"));
	# copy ctx->h[0-7] to A,B,C,D,E,F,G,H on stack
	&mov	($AH[0],&DWP(0,"esi"));
	&mov	($AH[1],&DWP(4,"esi"));
	&mov	("ecx",&DWP(8,"esi"));
	&mov	("ebx",&DWP(12,"esi"));
	#&mov	(&DWP(0,"esp"),$AH[0]);
	&mov	(&DWP(4,"esp"),$AH[1]);
	&xor	($AH[1],"ecx");		# magic
	&mov	(&DWP(8,"esp"),"ecx");
	&mov	(&DWP(12,"esp"),"ebx");
	&mov	($E,&DWP(16,"esi"));	
	&mov	("ebx",&DWP(20,"esi"));
	&mov	("ecx",&DWP(24,"esi"));
	&mov	("esi",&DWP(28,"esi"));
	#&mov	(&DWP(16,"esp"),$E);
	&mov	(&DWP(20,"esp"),"ebx");
	&mov	(&DWP(24,"esp"),"ecx");
	&mov	(&DWP(28,"esp"),"esi");
	&jmp	(&label("grand_loop"));

&set_label("grand_loop",16);
    # copy input block to stack reversing byte order
    for($i=0;$i<5;$i++) {
	&mov	("ebx",&DWP(12*$i+0,"edi"));
	&mov	("ecx",&DWP(12*$i+4,"edi"));
	&bswap	("ebx");
	&mov	("esi",&DWP(12*$i+8,"edi"));
	&bswap	("ecx");
	&mov	(&DWP(32+12*$i+0,"esp"),"ebx");
	&bswap	("esi");
	&mov	(&DWP(32+12*$i+4,"esp"),"ecx");
	&mov	(&DWP(32+12*$i+8,"esp"),"esi");
    }
	&mov	("ebx",&DWP($i*12,"edi"));
	&add	("edi",64);
	&bswap	("ebx");
	&mov	(&DWP(96+4,"esp"),"edi");
	&mov	(&DWP(32+12*$i,"esp"),"ebx");

    my ($t1,$t2) = ("ecx","esi");
    my ($a,$b,$c,$d,$e,$f,$g,$h)=(0..7);	# offsets
    sub off { &DWP(4*(((shift)-$i)&7),"esp"); }

    for ($i=0;$i<64;$i++) {

      if ($i>=16) {
	&mov	($T,$t1);			# $t1 is preloaded
	# &mov	($t2,&DWP(32+4*(($i+14)&15),"esp"));
	&ror	($t1,18-7);
	 &mov	("edi",$t2);
	&ror	($t2,19-17);
	 &xor	($t1,$T);
	 &shr	($T,3);
	&ror	($t1,7);
	 &xor	($t2,"edi");
	 &xor	($T,$t1);			# T = sigma0(X[-15])
	&ror	($t2,17);
	 &add	($T,&DWP(32+4*($i&15),"esp"));	# T += X[-16]
	&shr	("edi",10);
	 &add	($T,&DWP(32+4*(($i+9)&15),"esp"));	# T += X[-7]
	#&xor	("edi",$t2)			# sigma1(X[-2])
	# &add	($T,"edi");			# T += sigma1(X[-2])
	# &mov	(&DWP(4*(9+15),"esp"),$T);	# save X[0]
      }
	&mov	($t1,$E);
	 &xor	("edi",$t2)			if ($i>=16);	# sigma1(X[-2])
	 &mov	($t2,&off($f));
	&ror	($E,25-11);
	 &add	($T,"edi")			if ($i>=16);	# T += sigma1(X[-2])
	 &mov	("edi",&off($g));
	&xor	($E,$t1);
	 &mov	($T,&DWP(32+4*($i&15),"esp"))	if ($i<16);	# X[i]
	 &mov	(&DWP(32+4*($i&15),"esp"),$T)	if ($i>=16 && $i<62);	# save X[0]
	 &xor	($t2,"edi");
	&ror	($E,11-6);
	 &and	($t2,$t1);
	 &mov	(&off($e),$t1);		# save $E, modulo-scheduled
	&xor	($E,$t1);
	 &add	($T,&off($h));		# T += h
	 &xor	("edi",$t2);		# Ch(e,f,g)
	&ror	($E,6);			# Sigma1(e)
	 &mov	($t1,$AH[0]);
	 &add	($T,"edi");		# T += Ch(e,f,g)

	&ror	($t1,22-13);
	 &mov	($t2,$AH[0]);
	 &mov	("edi",&off($b));
	&xor	($t1,$AH[0]);
	 &mov	(&off($a),$AH[0]);	# save $A, modulo-scheduled
	 &xor	($AH[0],"edi");		# a ^= b, (b^c) in next round
	&ror	($t1,13-2);
	 &and	($AH[1],$AH[0]);	# (b^c) &= (a^b)
	 &lea	($E,&DWP(@K256[$i],$T,$E));	# T += Sigma1(1)+K[i]
	&xor	($t1,$t2);
	 &xor	($AH[1],"edi");		# h = Maj(a,b,c) = Ch(a^b,c,b)
	 &mov	($t2,&DWP(32+4*(($i+2)&15),"esp"))	if ($i>=15 && $i<63);
	&ror	($t1,2);		# Sigma0(a)

	 &add	($AH[1],$E);		# h += T
	 &add	($E,&off($d));		# d += T
	&add	($AH[1],$t1);		# h += Sigma0(a)
	 &mov	($t1,&DWP(32+4*(($i+15)&15),"esp"))	if ($i>=15 && $i<63);

	@AH = reverse(@AH);		# rotate(a,h)
	($t1,$t2) = ($t2,$t1);		# rotate(t1,t2)
    }
	&mov	("esi",&DWP(96,"esp"));	#ctx
					#&mov	($AH[0],&DWP(0,"esp"));
	&xor	($AH[1],"edi");		#&mov	($AH[1],&DWP(4,"esp"));
					#&mov	("edi", &DWP(8,"esp"));
	&mov	("ecx",&DWP(12,"esp"));
	&add	($AH[0],&DWP(0,"esi"));
	&add	($AH[1],&DWP(4,"esi"));
	&add	("edi",&DWP(8,"esi"));
	&add	("ecx",&DWP(12,"esi"));
	&mov	(&DWP(0,"esi"),$AH[0]);
	&mov	(&DWP(4,"esi"),$AH[1]);
	&mov	(&DWP(8,"esi"),"edi");
	&mov	(&DWP(12,"esi"),"ecx");
	 #&mov	(&DWP(0,"esp"),$AH[0]);
	 &mov	(&DWP(4,"esp"),$AH[1]);
	 &xor	($AH[1],"edi");		# magic
	 &mov	(&DWP(8,"esp"),"edi");
	 &mov	(&DWP(12,"esp"),"ecx");
	#&mov	($E,&DWP(16,"esp"));
	&mov	("edi",&DWP(20,"esp"));
	&mov	("ebx",&DWP(24,"esp"));
	&mov	("ecx",&DWP(28,"esp"));
	&add	($E,&DWP(16,"esi"));
	&add	("edi",&DWP(20,"esi"));
	&add	("ebx",&DWP(24,"esi"));
	&add	("ecx",&DWP(28,"esi"));
	&mov	(&DWP(16,"esi"),$E);
	&mov	(&DWP(20,"esi"),"edi");
	&mov	(&DWP(24,"esi"),"ebx");
	&mov	(&DWP(28,"esi"),"ecx");
	 #&mov	(&DWP(16,"esp"),$E);
	 &mov	(&DWP(20,"esp"),"edi");
	&mov	("edi",&DWP(96+4,"esp"));	# inp
	 &mov	(&DWP(24,"esp"),"ebx");
	 &mov	(&DWP(28,"esp"),"ecx");

	&cmp	("edi",&DWP(96+8,"esp"));	# are we done yet?
	&jb	(&label("grand_loop"));

	&mov	("esp",&DWP(96+12,"esp"));	# restore sp
&function_end_A();
}
&function_end_B("sha256_block_data_order");
&asciz("SHA256 block transform for x86, CRYPTOGAMS by <appro\@openssl.org>");

&asm_finish();
