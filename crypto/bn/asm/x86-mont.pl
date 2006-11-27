#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# October 2005
#
# This is a "teaser" code, as it can be improved in several ways...
# First of all non-SSE2 path should be implemented (yes, for now it
# performs Montgomery multiplication/convolution only on SSE2-capable
# CPUs such as P4, others fall down to original code). Then inner loop
# can be unrolled and modulo-scheduled to improve ILP and possibly
# moved to 128-bit XMM register bank (though it would require input
# rearrangement and/or increase bus bandwidth utilization). Dedicated
# squaring procedure should give further performance improvement...
# Yet, for being draft, the code improves rsa512 *sign* benchmark by
# 110%(!), rsa1024 one - by 70% and rsa4096 - by 20%:-)

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

$sse2=0;
for (@ARGV) { $sse2=1 if (/-DOPENSSL_IA32_SSE2/); }

&external_label("OPENSSL_ia32cap_P") if ($sse2);

&function_begin("bn_mul_mont",$sse2?"EXTRN\t_OPENSSL_ia32cap_P:DWORD":"");

$i="edx";
$j="ecx";
$ap="esi";
$rp="edi";	$bp="edi";		# overlapping variables!!!
$np="ebp";
$num="ebx";

$_rp=&DWP(4*0,"esp");			# stack top layout
$_ap=&DWP(4*1,"esp");
$_bp=&DWP(4*2,"esp");
$_np=&DWP(4*3,"esp");
$_n0=&DWP(4*4,"esp");
$_num=&DWP(4*5,"esp");
$_sp=&DWP(4*6,"esp");
$_bpend=&DWP(4*7,"esp");
$frame=32;				# size of above frame rounded up to 16n

	&xor	("eax","eax");
	&mov	("edi",&wparam(5));	# int num
	&cmp	("edi",3);
	&jb	(&label("just_leave"));

	################################# load argument block...
	&mov	("eax",&wparam(0));	# BN_ULONG *rp
	&mov	("ebx",&wparam(1));	# const BN_ULONG *ap
	&mov	("ecx",&wparam(2));	# const BN_ULONG *bp
	&mov	("edx",&wparam(3));	# const BN_ULONG *np
	&mov	("esi",&wparam(4));	# const BN_ULONG *n0
	#&mov	("edi",&wparam(5));	# int num

	&mov	("ebp","esp");		# saved stack pointer!
	&add	("edi",2);		# extra two words on top of tp
	&neg	("edi");
	&lea	("esp",&DWP(-$frame,"esp","edi",4));	# alloca($frame+4*(num+2))
	&neg	("edi");
	&and	("esp",-4096);		# minimize TLB utilization

	&mov	("esi",&DWP(0,"esi"));	# pull n0[0]
	&mov	($_rp,"eax");		# ... save a copy of argument block
	&mov	($_ap,"ebx");
	&mov	($_bp,"ecx");
	&mov	($_np,"edx");
	&mov	($_n0,"esi");
	&lea	($num,&DWP(-2,"edi"));	# num is restored to its original value
	#&mov	($_num,$num);		# redundant as $num is not reused
	&mov	($_sp,"ebp");		# saved stack pointer!

if($sse2) {
$acc0="mm0";	# mmx register bank layout
$acc1="mm1";
$car0="mm2";
$car1="mm3";
$mul0="mm4";
$mul1="mm5";
$temp="mm6";
$mask="mm7";

	&picmeup("eax","OPENSSL_ia32cap_P");
	&bt	(&DWP(0,"eax"),26);
	&jnc	(&label("non_sse2"));

	&mov	("eax",-1);
	&movd	($mask,"eax");		# mask 32 lower bits

	&mov	($ap,$_ap);		# load input pointers
	&mov	($bp,$_bp);
	&mov	($np,$_np);

	&xor	($i,$i);		# i=0
	&xor	($j,$j);		# j=0

	&movd	($mul0,&DWP(0,$bp));		# bp[0]
	&movd	($mul1,&DWP(0,$ap));		# ap[0]
	&movd	($car1,&DWP(0,$np));		# np[0]

	&pmuludq($mul1,$mul0);			# ap[0]*bp[0]
	&movq	($car0,$mul1);
	&movq	($acc0,$mul1);			# I wish movd worked for
	&pand	($acc0,$mask);			# inter-register transfers

	&pmuludq($mul1,$_n0);			# *=n0

	&pmuludq($car1,$mul1);			# "t[0]"*np[0]*n0
	&paddq	($car1,$acc0);

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&inc	($j);				# j++
&set_label("1st");
	&movd	($acc0,&DWP(0,$ap,$j,4));	# ap[j]
	&movd	($acc1,&DWP(0,$np,$j,4));	# np[j]
	&pmuludq($acc0,$mul0);			# ap[j]*bp[0]
	&pmuludq($acc1,$mul1);			# np[j]*m1

	&paddq	($car0,$acc0);			# +=c0
	&movq	($acc0,$car0);
	&pand	($acc0,$mask);

	&paddq	($car1,$acc1);			# +=c1
	&paddq	($car1,$acc0);			# +=ap[j]*bp[0];
	&movd	(&DWP($frame-4,"esp",$j,4),$car1);	# tp[j-1]=

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&lea	($j,&DWP(1,$j));
	&cmp	($j,$num);
	&jl	(&label("1st"));

	&paddq	($car1,$car0);
	&movq	(&DWP($frame-4,"esp",$num,4),$car1);

	&inc	($i);				# i++
&set_label("outer");
	&xor	($j,$j);			# j=0

	&movd	($mul0,&DWP(0,$bp,$i,4));	# bp[i]
	&movd	($mul1,&DWP(0,$ap));		# ap[0]
	&movd	($temp,&DWP($frame,"esp"));	# tp[0]
	&movd	($car1,&DWP(0,$np));		# np[0]
	&pmuludq($mul1,$mul0);			# ap[0]*bp[i]

	&paddq	($mul1,$temp);			# +=tp[0]
	&movq	($acc0,$mul1);
	&movq	($car0,$mul1);
	&pand	($acc0,$mask);

	&pmuludq($mul1,$_n0);			# *=n0

	&pmuludq($car1,$mul1);
	&paddq	($car1,$acc0);

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&inc	($j);				# j++
&set_label("inner");
	&movd	($acc0,&DWP(0,$ap,$j,4));	# ap[j]
	&movd	($acc1,&DWP(0,$np,$j,4));	# np[j]
	&movd	($temp,&DWP($frame,"esp",$j,4));# tp[j]
	&pmuludq($acc0,$mul0);			# ap[j]*bp[i]
	&pmuludq($acc1,$mul1);			# np[j]*m1
	&paddq	($car0,$temp);			# +=tp[j]
	&paddq	($car0,$acc0);			# +=c0
	&movq	($acc0,$car0);
	&pand	($acc0,$mask);

	&paddq	($car1,$acc1);			# +=c1
	&paddq	($car1,$acc0);			# +=ap[j]*bp[i]+tp[j]
	&movd	(&DWP($frame-4,"esp",$j,4),$car1);	# tp[j-1]=

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&lea	($j,&DWP(1,$j));		# j++
	&cmp	($j,$num);
	&jl	(&label("inner"));

	&movd	($temp,&DWP($frame,"esp",$num,4));
	&paddq	($car1,$car0);
	&paddq	($car1,$temp);
	&movq	(&DWP($frame-4,"esp",$num,4),$car1);

	&lea	($i,&DWP(1,$i));		# i++
	&cmp	($i,$num);
	&jl	(&label("outer"));

	&emms	();				# done with mmx bank
	&jmp	(&label("common_tail"));

&set_label("non_sse2",16);
}

if (1) {
	&mov	("esp",$_sp);
	&xor	("eax","eax");	# signal "not fast enough [yet]"
	&jmp	(&label("just_leave"));
	# The code below gives ~15% improvement on 512-bit benchmark
	# *only*:-( On all other key lengths it's slower for up to 20%.
	# This is because the original code path holds down the overall
	# amount of multiplications by ~25% by deploying bn_sqr_words.
	# In other words, for the code below to be competitive,
	# dedicated squaring procedure is a must...
} else {
$inp="esi";	# integer path uses these registers differently
$word="edi";
$carry="ebp";

	&sub	($num,1);		# non-SSE2 path uses num-1

	&mov	($inp,$_ap);
	&mov	($word,$_bp);
	&lea	("eax",&DWP(4,$word,$num,4));		# &bp[num]
	&mov	($word,&DWP(0,$word));			# bp[0]
	&mov	($_bpend,"eax");
	&xor	($j,$j);
	&xor	("edx","edx");

&set_label("mull",16);
	&mov	("eax",&DWP(0,$inp,$j,4));		# ap[j]
	&mov	($carry,"edx");
	&mul	($word);				# ap[j]*bp[0]
	&lea	($j,&DWP(1,$j));
	&add	("eax",$carry);
	&adc	("edx",0);
	&mov	(&DWP($frame-4,"esp",$j,4),"eax");	# tp[j]=
	&cmp	($j,$num);
	&jb	(&label("mull"));

	&mov	("eax",&DWP(0,$inp,$num,4));		# ap[num-1]
	&mov	($carry,"edx");
	&mul	($word);				# ap[num-1]*bp[0]
	&add	("eax",$carry);
	&adc	("edx",0);

	&mov	($word,$_n0);
	&mov	($inp,$_np);
	&imul	($word,&DWP($frame,"esp"));		# n0*tp[0]

	&mov	(&DWP($frame,"esp",$num,4),"eax");	# tp[num-1]=
	&xor	($j,$j);
	&mov	(&DWP($frame+4,"esp",$num,4),"edx");	# tp[num]=
	&mov	(&DWP($frame+8,"esp",$num,4),$j);	# tp[num+1]=

	&mov	("eax",&DWP(0,$inp));			# np[0]
	&mul	($word);				# np[0]*m
	&add	("eax",&DWP($frame,"esp"));		# +=tp[0]
	&adc	("edx",0);
	&mov	($j,1);

	&jmp	(&label("2ndmadd"));

&set_label("1stmadd",16);
	&mov	("eax",&DWP(0,$inp,$j,4));		# ap[j]
	&mov	($carry,"edx");
	&mul	($word);				# ap[j]*bp[i]
	&lea	($j,&DWP(1,$j));
	&add	("eax",&DWP($frame-4,"esp",$j,4));	# +=tp[j]
	&adc	("edx",0);
	&add	("eax",$carry);
	&adc	("edx",0);
	&mov	(&DWP($frame-4,"esp",$j,4),"eax");	# tp[j]=
	&cmp	($j,$num);
	&jb	(&label("1stmadd"));

	&mov	("eax",&DWP(0,$inp,$num,4));		# ap[num-1]
	&mov	($carry,"edx");
	&mul	($word);				# ap[num-1]*bp[i]
	&add	("eax",&DWP($frame,"esp",$num,4));	# +=tp[num-1]
	&adc	("edx",0);
	&add	("eax",$carry);
	&adc	("edx",0);

	&mov	($word,$_n0);
	&mov	($inp,$_np);
	&imul	($word,&DWP($frame,"esp"));		# n0*tp[0]

	&xor	($j,$j);
	&add	("edx",&DWP($frame+4,"esp",$num,4));	# carry+=tp[num]
	&mov	(&DWP($frame,"esp",$num,4),"eax");	# tp[num-1]=
	&adc	($j,0);
	&mov	(&DWP($frame+4,"esp",$num,4),"edx");	# tp[num]=
	&mov	(&DWP($frame+8,"esp",$num,4),$j);	# tp[num+1]=

	&mov	("eax",&DWP(0,$inp));			# np[0]
	&mul	($word);				# np[0]*m
	&add	("eax",&DWP($frame,"esp"));		# +=tp[0]
	&adc	("edx",0);
	&mov	($j,1);

&set_label("2ndmadd",16);
	&mov	("eax",&DWP(0,$inp,$j,4));		# np[j]
	&mov	($carry,"edx");
	&mul	($word);				# np[j]*m
	&lea	($j,&DWP(1,$j));
	&add	("eax",&DWP($frame-4,"esp",$j,4));	# +=tp[j]
	&adc	("edx",0);
	&add	("eax",$carry);
	&adc	("edx",0);
	&mov	(&DWP($frame-8,"esp",$j,4),"eax");	# tp[j-1]=
	&cmp	($j,$num);
	&jb	(&label("2ndmadd"));

	&mov	("eax",&DWP(0,$inp,$num,4));		# np[num-1]
	&mov	($carry,"edx");
	&mul	($word);				# np[num-1]*m
	&add	("eax",&DWP($frame,"esp",$num,4));	# +=tp[num-1]
	&adc	("edx",0);
	&add	("eax",$carry);
	&adc	("edx",0);
	&mov	(&DWP($frame-4,"esp",$num,4),"eax");	# tp[num-2]=

	&xor	("eax","eax");
	&add	("edx",&DWP($frame+4,"esp",$num,4));	# carry+=tp[num]
	&adc	("eax",&DWP($frame+8,"esp",$num,4));	# +=tp[num+1]
	&mov	(&DWP($frame,"esp",$num,4),"edx");	# tp[num-1]=
	&mov	(&DWP($frame+4,"esp",$num,4),"eax");	# tp[num]=

	&mov	($carry,$_bp);				# &bp[i]
	&add	($carry,4);
	&cmp	($carry,$_bpend);
	&je	(&label("x86done"));
	&mov	($word,&DWP(0,$carry));			# bp[i]
	&mov	($inp,$_ap);
	&mov	($_bp,$carry);				# &bp[++i]
	&xor	($j,$j);
	&xor	("edx","edx");
	&jmp	(&label("1stmadd"));

&set_label("x86done",16);
	&mov	($np,$_np);	# make adjustments for tail processing
	&add	($num,1);
}

&set_label("common_tail",16);
	&mov	("esi",&DWP($frame,"esp",$num,4));# load upmost overflow bit
	&mov	($rp,$_rp);			# load result pointer
						# [$ap and $bp are zapped]
	&xor	($i,$i);			# i=0
	&lea	($j,&DWP(-1,$num));		# j=num-1
	&cmp	("esi",0);			# clears CF unconditionally
	&jnz	(&label("sub"));
	&mov	("eax",&DWP($frame,"esp",$j,4));
	&cmp	("eax",&DWP(0,$np,$j,4));	# tp[num-1]-np[num-1]?
	&jae	(&label("sub"));		# if taken CF is cleared
&set_label("copy",16);
	&mov	("eax",&DWP($frame,"esp",$j,4));
	&mov	(&DWP(0,$rp,$j,4),"eax");	# rp[i]=tp[i]
	&mov	(&DWP($frame,"esp",$j,4),$j);	# zap temporary vector
	&dec	($j);
	&jge	(&label("copy"));
	&jmp	(&label("exit"));

&set_label("sub",16);
	&mov	("eax",&DWP($frame,"esp",$i,4));
	&sbb	("eax",&DWP(0,$np,$i,4));
	&mov	(&DWP(0,$rp,$i,4),"eax");	# rp[i]=tp[i]-np[i]
	&lea	($i,&DWP(1,$i));		# i++
	&dec	($j);				# doesn't affect CF!
	&jge	(&label("sub"));
	&lea	($j,&DWP(-1,$num));		# j=num-1
	&sbb	("esi",0);			# esi holds upmost overflow bit
	&jc	(&label("copy"));
&set_label("zap",16);
	&mov	(&DWP($frame,"esp",$j,4),$i);	# zap temporary vector
	&dec	($j);
	&jge	(&label("zap"));

&set_label("exit",4);
	&mov	("esp",$_sp);		# pull saved stack pointer
	&mov	("eax",1);
&set_label("just_leave");
&function_end("bn_mul_mont");

&asm_finish();
