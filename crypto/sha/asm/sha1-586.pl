#!/usr/local/bin/perl

# It was noted that Intel IA-32 C compiler generates code which
# performs ~30% *faster* on P4 CPU than original *hand-coded*
# SHA1 assembler implementation. To address this problem (and
# prove that humans are still better than machines:-), the
# original code was overhauled, which resulted in following
# performance changes:
#
#		compared with original	compared with Intel cc
#		assembler impl.		generated code
# Pentium	-16%			+48%
# PIII/AMD	+8%			+16%
# P4		+85%(!)			+45%
#
# As you can see Pentium came out as looser:-( Yet I reckoned that
# improvement on P4 outweights the loss and incorporate this
# re-tuned code to 0.9.7 and later.
# ----------------------------------------------------------------
# Those who for any particular reason absolutely must score on
# Pentium can replace this module with one from 0.9.6 distribution.
# This "offer" shall be revoked the moment programming interface to
# this module is changed, in which case this paragraph should be
# removed.
# ----------------------------------------------------------------
#					<appro@fy.chalmers.se>

$normal=0;

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"sha1-586.pl",$ARGV[$#ARGV] eq "386");

$A="eax";
$B="ecx";
$C="ebx";
$D="edx";
$E="edi";
$T="esi";
$tmp1="ebp";

$off=9*4;

@K=(0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6);

&sha1_block_data("sha1_block_asm_data_order");

&asm_finish();

sub Nn
	{
	local($p)=@_;
	local(%n)=($A,$T,$B,$A,$C,$B,$D,$C,$E,$D,$T,$E);
	return($n{$p});
	}

sub Np
	{
	local($p)=@_;
	local(%n)=($A,$T,$B,$A,$C,$B,$D,$C,$E,$D,$T,$E);
	local(%n)=($A,$B,$B,$C,$C,$D,$D,$E,$E,$T,$T,$A);
	return($n{$p});
	}

sub Na
	{
	local($n)=@_;
	return( (($n   )&0x0f),
		(($n+ 2)&0x0f),
		(($n+ 8)&0x0f),
		(($n+13)&0x0f),
		(($n+ 1)&0x0f));
	}

sub X_expand
	{
	local($in)=@_;

	&comment("First, load the words onto the stack in network byte order");
	for ($i=0; $i<16; $i+=2)
		{
		&mov($A,&DWP(($i+0)*4,$in,"",0));# unless $i == 0;
		 &mov($B,&DWP(($i+1)*4,$in,"",0));
		&bswap($A);
		 &bswap($B);
		&mov(&swtmp($i+0),$A);
		 &mov(&swtmp($i+1),$B);
		}

	&comment("We now have the X array on the stack");
	&comment("starting at sp-4");
	}

# Rules of engagement
# F is always trashable at the start, the running total.
# E becomes the next F so it can be trashed after it has been 'accumulated'
# F becomes A in the next round.  We don't need to access it much.
# During the X update part, the result ends up in $X[$n0].

sub BODY_00_15
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;

	&comment("00_15 $n");

	&mov($f,$c);			# f to hold F_00_19(b,c,d)
	 if ($n==0)  { &mov($tmp1,$a); }
	 else        { &mov($a,$tmp1); }
	&rotl($tmp1,5);			# tmp1=ROTATE(a,5)
	 &xor($f,$d);
	&and($f,$b);
	 &add($tmp1,$e);		# tmp1+=e;
	&mov($e,&swtmp($n));		# e becomes volatile and
	 				# is loaded with xi
	 &xor($f,$d);			# f holds F_00_19(b,c,d)
	&rotr($b,2);			# b=ROTATE(b,30)
	 &lea($tmp1,&DWP($K,$tmp1,$e,1));# tmp1+=K_00_19+xi

	if ($n==15) { &add($f,$tmp1); }	# f+=tmp1
	else        { &add($tmp1,$f); }
	}

sub BODY_16_19
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

	&comment("16_19 $n");

	&mov($f,&swtmp($n1));		# f to hold Xupdate(xi,xa,xb,xc,xd)
	 &mov($tmp1,$c);		# tmp1 to hold F_00_19(b,c,d)
	&xor($f,&swtmp($n0));
	 &xor($tmp1,$d);
	&xor($f,&swtmp($n2));
	 &and($tmp1,$b);		# tmp1 holds F_00_19(b,c,d)
	&rotr($b,2);			# b=ROTATE(b,30)
	 &xor($f,&swtmp($n3));		# f holds xa^xb^xc^xd
	&rotl($f,1);			# f=ROATE(f,1)
	 &xor($tmp1,$d);		# tmp1=F_00_19(b,c,d)
	&mov(&swtmp($n0),$f);		# xi=f
	&lea($f,&DWP($K,$f,$e,1));	# f+=K_00_19+e
	 &mov($e,$a);			# e becomes volatile
	&rotl($e,5);			# e=ROTATE(a,5)
	 &add($f,$tmp1);		# f+=F_00_19(b,c,d)
	&add($f,$e);			# f+=ROTATE(a,5)
	}

sub BODY_20_39
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;

	&comment("20_39 $n");
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

	&mov($tmp1,$b);			# tmp1 to hold F_20_39(b,c,d)
	 &mov($f,&swtmp($n0));		# f to hold Xupdate(xi,xa,xb,xc,xd)
	&rotr($b,2);			# b=ROTATE(b,30)
	 &xor($f,&swtmp($n1));
	&xor($tmp1,$c);
	 &xor($f,&swtmp($n2));
	&xor($tmp1,$d);			# tmp1 holds F_20_39(b,c,d)
	 &xor($f,&swtmp($n3));		# f holds xa^xb^xc^xd
	&rotl($f,1);			# f=ROTATE(f,1)
	 &add($tmp1,$e);
	&mov(&swtmp($n0),$f);		# xi=f
	 &mov($e,$a);			# e becomes volatile
	&rotl($e,5);			# e=ROTATE(a,5)
	 &lea($f,&DWP($K,$f,$tmp1,1));	# f+=K_20_39+e
	&add($f,$e);			# f+=ROTATE(a,5)
	}

sub BODY_40_59
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;

	&comment("40_59 $n");
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

	&mov($f,&swtmp($n0));		# f to hold Xupdate(xi,xa,xb,xc,xd)
	 &mov($tmp1,&swtmp($n1));
	&xor($f,$tmp1);
	 &mov($tmp1,&swtmp($n2));
	&xor($f,$tmp1);
	 &mov($tmp1,&swtmp($n3));
	&xor($f,$tmp1);			# f holds xa^xb^xc^xd
	 &mov($tmp1,$b);		# tmp1 to hold F_40_59(b,c,d)
	&rotl($f,1);			# f=ROTATE(f,1)
	 &or($tmp1,$c);
	&mov(&swtmp($n0),$f);		# xi=f
	 &and($tmp1,$d);
	&lea($f,&DWP($K,$f,$e,1));	# f+=K_40_59+e
	 &mov($e,$b);			# e becomes volatile and is used
					# to calculate F_40_59(b,c,d)
	&rotr($b,2);			# b=ROTATE(b,30)
	 &and($e,$c);
	&or($tmp1,$e);			# tmp1 holds F_40_59(b,c,d)		
	 &mov($e,$a);
	&rotl($e,5);			# e=ROTATE(a,5)
	 &add($f,$tmp1);		# f+=tmp1;
	&add($f,$e);			# f+=ROTATE(a,5)
	}

sub BODY_60_79
	{
	&BODY_20_39(@_);
	}

sub sha1_block_host
	{
	local($name, $sclabel)=@_;

	&function_begin_B($name,"");

	# parameter 1 is the MD5_CTX structure.
	# A	0
	# B	4
	# C	8
	# D 	12
	# E 	16

	&mov("ecx",	&wparam(2));
	 &push("esi");
	&shl("ecx",6);
	 &mov("esi",	&wparam(1));
	&push("ebp");
	 &add("ecx","esi");	# offset to leave on
	&push("ebx");
	 &mov("ebp",	&wparam(0));
	&push("edi");
	 &mov($D,	&DWP(12,"ebp","",0));
	&stack_push(18+9);
	 &mov($E,	&DWP(16,"ebp","",0));
	&mov($C,	&DWP( 8,"ebp","",0));
	 &mov(&swtmp(17),"ecx");

	&comment("First we need to setup the X array");

	for ($i=0; $i<16; $i+=2)
		{
		&mov($A,&DWP(($i+0)*4,"esi","",0));# unless $i == 0;
		 &mov($B,&DWP(($i+1)*4,"esi","",0));
		&mov(&swtmp($i+0),$A);
		 &mov(&swtmp($i+1),$B);
		}
	&jmp($sclabel);
	&function_end_B($name);
	}


sub sha1_block_data
	{
	local($name)=@_;

	&function_begin_B($name,"");

	# parameter 1 is the MD5_CTX structure.
	# A	0
	# B	4
	# C	8
	# D 	12
	# E 	16

	&mov("ecx",	&wparam(2));
	 &push("esi");
	&shl("ecx",6);
	 &mov("esi",	&wparam(1));
	&push("ebp");
	 &add("ecx","esi");	# offset to leave on
	&push("ebx");
	 &mov("ebp",	&wparam(0));
	&push("edi");
	 &mov($D,	&DWP(12,"ebp","",0));
	&stack_push(18+9);
	 &mov($E,	&DWP(16,"ebp","",0));
	&mov($C,	&DWP( 8,"ebp","",0));
	 &mov(&swtmp(17),"ecx");

	&comment("First we need to setup the X array");

	&set_label("start") unless $normal;

	&X_expand("esi");
	 &mov(&wparam(1),"esi");

	&set_label("shortcut", 0, 1);
	&comment("");
	&comment("Start processing");

	# odd start
	&mov($A,	&DWP( 0,"ebp","",0));
	 &mov($B,	&DWP( 4,"ebp","",0));
	$X="esp";
	&BODY_00_15(-2,$K[0],$X, 0,$A,$B,$C,$D,$E,$T);
	&BODY_00_15( 0,$K[0],$X, 1,$T,$A,$B,$C,$D,$E);
	&BODY_00_15( 0,$K[0],$X, 2,$E,$T,$A,$B,$C,$D);
	&BODY_00_15( 0,$K[0],$X, 3,$D,$E,$T,$A,$B,$C);
	&BODY_00_15( 0,$K[0],$X, 4,$C,$D,$E,$T,$A,$B);
	&BODY_00_15( 0,$K[0],$X, 5,$B,$C,$D,$E,$T,$A);
	&BODY_00_15( 0,$K[0],$X, 6,$A,$B,$C,$D,$E,$T);
	&BODY_00_15( 0,$K[0],$X, 7,$T,$A,$B,$C,$D,$E);
	&BODY_00_15( 0,$K[0],$X, 8,$E,$T,$A,$B,$C,$D);
	&BODY_00_15( 0,$K[0],$X, 9,$D,$E,$T,$A,$B,$C);
	&BODY_00_15( 0,$K[0],$X,10,$C,$D,$E,$T,$A,$B);
	&BODY_00_15( 0,$K[0],$X,11,$B,$C,$D,$E,$T,$A);
	&BODY_00_15( 0,$K[0],$X,12,$A,$B,$C,$D,$E,$T);
	&BODY_00_15( 0,$K[0],$X,13,$T,$A,$B,$C,$D,$E);
	&BODY_00_15( 0,$K[0],$X,14,$E,$T,$A,$B,$C,$D);
	&BODY_00_15( 1,$K[0],$X,15,$D,$E,$T,$A,$B,$C);
	&BODY_16_19(-1,$K[0],$X,16,$C,$D,$E,$T,$A,$B);
	&BODY_16_19( 0,$K[0],$X,17,$B,$C,$D,$E,$T,$A);
	&BODY_16_19( 0,$K[0],$X,18,$A,$B,$C,$D,$E,$T);
	&BODY_16_19( 1,$K[0],$X,19,$T,$A,$B,$C,$D,$E);

	&BODY_20_39(-1,$K[1],$X,20,$E,$T,$A,$B,$C,$D);
	&BODY_20_39( 0,$K[1],$X,21,$D,$E,$T,$A,$B,$C);
	&BODY_20_39( 0,$K[1],$X,22,$C,$D,$E,$T,$A,$B);
	&BODY_20_39( 0,$K[1],$X,23,$B,$C,$D,$E,$T,$A);
	&BODY_20_39( 0,$K[1],$X,24,$A,$B,$C,$D,$E,$T);
	&BODY_20_39( 0,$K[1],$X,25,$T,$A,$B,$C,$D,$E);
	&BODY_20_39( 0,$K[1],$X,26,$E,$T,$A,$B,$C,$D);
	&BODY_20_39( 0,$K[1],$X,27,$D,$E,$T,$A,$B,$C);
	&BODY_20_39( 0,$K[1],$X,28,$C,$D,$E,$T,$A,$B);
	&BODY_20_39( 0,$K[1],$X,29,$B,$C,$D,$E,$T,$A);
	&BODY_20_39( 0,$K[1],$X,30,$A,$B,$C,$D,$E,$T);
	&BODY_20_39( 0,$K[1],$X,31,$T,$A,$B,$C,$D,$E);
	&BODY_20_39( 0,$K[1],$X,32,$E,$T,$A,$B,$C,$D);
	&BODY_20_39( 0,$K[1],$X,33,$D,$E,$T,$A,$B,$C);
	&BODY_20_39( 0,$K[1],$X,34,$C,$D,$E,$T,$A,$B);
	&BODY_20_39( 0,$K[1],$X,35,$B,$C,$D,$E,$T,$A);
	&BODY_20_39( 0,$K[1],$X,36,$A,$B,$C,$D,$E,$T);
	&BODY_20_39( 0,$K[1],$X,37,$T,$A,$B,$C,$D,$E);
	&BODY_20_39( 0,$K[1],$X,38,$E,$T,$A,$B,$C,$D);
	&BODY_20_39( 1,$K[1],$X,39,$D,$E,$T,$A,$B,$C);

	&BODY_40_59(-1,$K[2],$X,40,$C,$D,$E,$T,$A,$B);
	&BODY_40_59( 0,$K[2],$X,41,$B,$C,$D,$E,$T,$A);
	&BODY_40_59( 0,$K[2],$X,42,$A,$B,$C,$D,$E,$T);
	&BODY_40_59( 0,$K[2],$X,43,$T,$A,$B,$C,$D,$E);
	&BODY_40_59( 0,$K[2],$X,44,$E,$T,$A,$B,$C,$D);
	&BODY_40_59( 0,$K[2],$X,45,$D,$E,$T,$A,$B,$C);
	&BODY_40_59( 0,$K[2],$X,46,$C,$D,$E,$T,$A,$B);
	&BODY_40_59( 0,$K[2],$X,47,$B,$C,$D,$E,$T,$A);
	&BODY_40_59( 0,$K[2],$X,48,$A,$B,$C,$D,$E,$T);
	&BODY_40_59( 0,$K[2],$X,49,$T,$A,$B,$C,$D,$E);
	&BODY_40_59( 0,$K[2],$X,50,$E,$T,$A,$B,$C,$D);
	&BODY_40_59( 0,$K[2],$X,51,$D,$E,$T,$A,$B,$C);
	&BODY_40_59( 0,$K[2],$X,52,$C,$D,$E,$T,$A,$B);
	&BODY_40_59( 0,$K[2],$X,53,$B,$C,$D,$E,$T,$A);
	&BODY_40_59( 0,$K[2],$X,54,$A,$B,$C,$D,$E,$T);
	&BODY_40_59( 0,$K[2],$X,55,$T,$A,$B,$C,$D,$E);
	&BODY_40_59( 0,$K[2],$X,56,$E,$T,$A,$B,$C,$D);
	&BODY_40_59( 0,$K[2],$X,57,$D,$E,$T,$A,$B,$C);
	&BODY_40_59( 0,$K[2],$X,58,$C,$D,$E,$T,$A,$B);
	&BODY_40_59( 1,$K[2],$X,59,$B,$C,$D,$E,$T,$A);

	&BODY_60_79(-1,$K[3],$X,60,$A,$B,$C,$D,$E,$T);
	&BODY_60_79( 0,$K[3],$X,61,$T,$A,$B,$C,$D,$E);
	&BODY_60_79( 0,$K[3],$X,62,$E,$T,$A,$B,$C,$D);
	&BODY_60_79( 0,$K[3],$X,63,$D,$E,$T,$A,$B,$C);
	&BODY_60_79( 0,$K[3],$X,64,$C,$D,$E,$T,$A,$B);
	&BODY_60_79( 0,$K[3],$X,65,$B,$C,$D,$E,$T,$A);
	&BODY_60_79( 0,$K[3],$X,66,$A,$B,$C,$D,$E,$T);
	&BODY_60_79( 0,$K[3],$X,67,$T,$A,$B,$C,$D,$E);
	&BODY_60_79( 0,$K[3],$X,68,$E,$T,$A,$B,$C,$D);
	&BODY_60_79( 0,$K[3],$X,69,$D,$E,$T,$A,$B,$C);
	&BODY_60_79( 0,$K[3],$X,70,$C,$D,$E,$T,$A,$B);
	&BODY_60_79( 0,$K[3],$X,71,$B,$C,$D,$E,$T,$A);
	&BODY_60_79( 0,$K[3],$X,72,$A,$B,$C,$D,$E,$T);
	&BODY_60_79( 0,$K[3],$X,73,$T,$A,$B,$C,$D,$E);
	&BODY_60_79( 0,$K[3],$X,74,$E,$T,$A,$B,$C,$D);
	&BODY_60_79( 0,$K[3],$X,75,$D,$E,$T,$A,$B,$C);
	&BODY_60_79( 0,$K[3],$X,76,$C,$D,$E,$T,$A,$B);
	&BODY_60_79( 0,$K[3],$X,77,$B,$C,$D,$E,$T,$A);
	&BODY_60_79( 0,$K[3],$X,78,$A,$B,$C,$D,$E,$T);
	&BODY_60_79( 2,$K[3],$X,79,$T,$A,$B,$C,$D,$E);

	&comment("End processing");
	&comment("");
	# D is the tmp value

	# E -> A
	# T -> B
	# A -> C
	# B -> D
	# C -> E
	# D -> T

	&mov($tmp1,&wparam(0));

	 &mov($D,	&DWP(12,$tmp1,"",0));
	&add($D,$B);
	 &mov($B,	&DWP( 4,$tmp1,"",0));
	&add($B,$T);
	 &mov($T,	$A);
	&mov($A,	&DWP( 0,$tmp1,"",0));
	 &mov(&DWP(12,$tmp1,"",0),$D);

	&add($A,$E);
	 &mov($E,	&DWP(16,$tmp1,"",0));
	&add($E,$C);
	 &mov($C,	&DWP( 8,$tmp1,"",0));
	&add($C,$T);

	 &mov(&DWP( 0,$tmp1,"",0),$A);
	&mov("esi",&wparam(1));
	 &mov(&DWP( 8,$tmp1,"",0),$C);
 	&add("esi",64);
	 &mov("eax",&swtmp(17));
	&mov(&DWP(16,$tmp1,"",0),$E);
	 &cmp("esi","eax");
	&mov(&DWP( 4,$tmp1,"",0),$B);
	 &jb(&label("start"));

	&stack_pop(18+9);
	 &pop("edi");
	&pop("ebx");
	 &pop("ebp");
	&pop("esi");
	 &ret();

	# keep a note of shortcut label so it can be used outside
	# block.
	my $sclabel = &label("shortcut");

	&function_end_B($name);
	# Putting this here avoids problems with MASM in debugging mode
	&sha1_block_host("sha1_block_asm_host_order", $sclabel);
	}

