#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================

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

$i="ebx";
$j="ecx";
$ap="esi";
$rp="edi";	$bp="edi";		# overlapping variables!!!
$np="edx";
$num="ebp";
$tp="esp";

$bias=2;				# amount of extra words in tp
					# (rounded up to even value)
$_rp=&DWP(4*($bias+0),"esp",$num,4);	# stack frame layout below tp
$_ap=&DWP(4*($bias+1),"esp",$num,4);
$_bp=&DWP(4*($bias+2),"esp",$num,4);
$_np=&DWP(4*($bias+3),"esp",$num,4);
$_n0=&DWP(4*($bias+4),"esp",$num,4);
$_sp=&DWP(4*($bias+5),"esp",$num,4);

$acc0="mm0";				# mmx register bank layout
$acc1="mm1";
$car0="mm2";
$car1="mm3";
$mul0="mm4";
$mul1="mm5";
$temp="mm6";
$mask="mm7";

if($sse2) {
	&picmeup("eax","OPENSSL_ia32cap_P");
	&bt	(&DWP(0,"eax"),26);
	&mov	("eax",0);		# zero signals "we did nothing"
	&jnc	(&label("non_sse2"));

	################################# load argument block...
	&mov	("eax",&wparam(0));	# BN_ULONG *rp
	&mov	("ebx",&wparam(1));	# const BN_ULONG *ap
	&mov	("ecx",&wparam(2));	# const BN_ULONG *bp
	&mov	("edx",&wparam(3));	# const BN_ULONG *np
	&mov	("esi",&wparam(4));	# BN_ULONG n0
	&mov	($num,&wparam(5));	# int num

	&mov	("edi","esp");		# saved stack pointer!
	&add	($num,$bias+6);
	&neg	($num);
	&lea	("esp",&DWP(0,"esp",$num,4));	# alloca(4*(num+$bias+6))
	&neg	($num);
	&and	("esp",-1024);		# minimize TLB utilization
	&sub	($num,$bias+6);		# num is restored to its original value
					# and will remain constant from now...

	&mov	($_rp,"eax");		# ... save a copy of argument block
	&mov	($_ap,"ebx");
	&mov	($_bp,"ecx");
	&mov	($_np,"edx");
	&mov	($_n0,"esi");
	&mov	($_sp,"edi");		# saved stack pointer!

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
	&movd	(&DWP(-4,"esp",$j,4),$car1);	# tp[j-1]=

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&lea	($j,&DWP(1,$j));
	&cmp	($j,$num);
	&jl	(&label("1st"));

	&paddq	($car1,$car0);
	&movq	(&DWP(-4,"esp",$num,4),$car1);

	&inc	($i);				# i++
&set_label("outer");
	&xor	($j,$j);			# j=0

	&movd	($mul0,&DWP(0,$bp,$i,4));	# bp[i]
	&movd	($mul1,&DWP(0,$ap));		# ap[0]
	&movd	($temp,&DWP(0,"esp"));		# tp[0]
	&movd	($car1,&DWP(0,$np,$j,4));	# np[0]
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
	&movd	($temp,&DWP(0,"esp",$j,4));	# tp[j]
	&pmuludq($acc0,$mul0);			# ap[j]*bp[i]
	&pmuludq($acc1,$mul1);			# np[j]*m1
	&paddq	($car0,$temp);			# +=tp[j]
	&paddq	($car0,$acc0);			# +=c0
	&movq	($acc0,$car0);
	&pand	($acc0,$mask);

	&paddq	($car1,$acc1);			# +=c1
	&paddq	($car1,$acc0);			# +=ap[j]*bp[i]+tp[j]
	&movd	(&DWP(-4,"esp",$j,4),$car1);	# tp[j-1]

	&psrlq	($car0,32);
	&psrlq	($car1,32);

	&lea	($j,&DWP(1,$j));		# j++
	&cmp	($j,$num);
	&jl	(&label("inner"));

	&movd	($temp,&DWP(0,"esp",$num,4));
	&paddq	($car1,$car0);
	&paddq	($car1,$temp);
	&movq	(&DWP(-4,"esp",$num,4),$car1);

	&lea	($i,&DWP(1,$i));		# i++
	&cmp	($i,$num);
	&jl	(&label("outer"));

	&emms	();				# done with mmx bank

	&mov	("esi",&DWP(0,"esp",$num,4));	# load upmost overflow bit
	&mov	($rp,$_rp);			# load result pointer
						# [$ap and $bp are zapped]
	&xor	($i,$i);			# i=0
	&lea	($j,&DWP(-1,$num));		# j=num-1
	&cmp	("esi",0);			# clears CF unconditionally
	&jnz	(&label("sub"));
	&mov	("eax",&DWP(0,"esp",$j,4));
	&cmp	("eax",&DWP(0,$np,$j,4));	# tp[num-1]-np[num-1]?
	&jae	(&label("sub"));		# if taken CF is cleared
&set_label("copy");
	&mov	("eax",&DWP(0,"esp",$j,4));
	&mov	(&DWP(0,$rp,$j,4),"eax");	# rp[i]=tp[i]
	&mov	(&DWP(0,"esp",$j,4),$j);	# zap temporary vector
	&dec	($j);
	&jge	(&label("copy"));
	&jmp	(&label("exit_sse2"));

&set_label("sub",4);
	&mov	("eax",&DWP(0,"esp",$i,4));
	&sbb	("eax",&DWP(0,$np,$i,4));
	&mov	(&DWP(0,$rp,$i,4),"eax");	# rp[i]=tp[i]-np[i]
	&lea	($i,&DWP(1,$i));		# i++
	&dec	($j);				# doesn't affect CF!
	&jge	(&label("sub"));
	&lea	($j,&DWP(-1,$num));		# j=num-1
	&sbb	("esi",0);			# esi holds upmost overflow bit
	&jc	(&label("copy"));
&set_label("zap");
	&mov	(&DWP(0,"esp",$j,4),$i);	# zap temporary vector
	&dec	($j);
	&jge	(&label("zap"));

&set_label("exit_sse2");
	&mov	("esp",$_sp);		# pull saved stack pointer
	&mov	("eax",1);
&set_label("non_sse2");
}

&function_end("bn_mul_mont");

&asm_finish();
