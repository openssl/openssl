#!/usr/local/bin/perl

$normal=0;

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"sha1-586.pl",$ARGV[$#ARGV] eq "386");

$A="eax";
$B="ebx";
$C="ecx";
$D="edx";
$E="edi";
$T="esi";
$tmp1="ebp";

$off=9*4;

@K=(0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6);

&sha1_block("sha1_block_x86");

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
	for ($i=0; $i<16; $i++)
		{
		&mov("eax",&DWP(($i+0)*4,$in,"",0)) unless $i == 0;
		&bswap("eax");
		&mov(&swtmp($i+0),"eax");
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

return if $n & 1;
	&comment("00_15 $n");

	 &mov($f,$c);

	&mov($tmp1,$a);
	 &xor($f,$d);			# F2

	&rotl($tmp1,5);			# A2

	&and($f,$b);			# F3
	 &add($tmp1,$e);

	&rotr($b,1);			# B1	<- F
	 &mov($e,&swtmp($n));		# G1

	&rotr($b,1);			# B1	<- F
	 &xor($f,$d);			# F4

	&lea($tmp1,&DWP($K,$tmp1,$e,1));

############################
#	&BODY_40_59( 0,$K[2],$X,42,$A,$B,$C,$D,$E,$T);
#	&BODY_40_59( 0,$K[2],$X,43,$T,$A,$B,$C,$D,$E);
$n++;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);
	($b,$c,$d,$e,$f,$a)=($a,$b,$c,$d,$e,$f);

	 &mov($f,$c);

	&add($a,$tmp1);		# MOVED DOWN
	 &xor($f,$d);			# F2

	&mov($tmp1,$a);
	 &and($f,$b);			# F3

	&rotl($tmp1,5);			# A2

	&add($tmp1,$e);
	 &mov($e,&swtmp($n));		# G1

	&rotr($b,1);			# B1	<- F
	 &xor($f,$d);			# F4

	&rotr($b,1);			# B1	<- F
	 &lea($tmp1,&DWP($K,$tmp1,$e,1));

	&add($f,$tmp1);
	}

sub BODY_16_19
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

return if $n & 1;
	&comment("16_19 $n");

 &nop() if ($pos < 0);
&mov($tmp1,&swtmp($n0));			# X1
 &mov($f,&swtmp($n1));			# X2
&xor($f,$tmp1);				# X3
 &mov($tmp1,&swtmp($n2));		# X4
&xor($f,$tmp1);				# X5
 &mov($tmp1,&swtmp($n3));		# X6
&xor($f,$tmp1);				# X7 - slot
 &mov($tmp1,$c);			# F1
&rotl($f,1);				# X8 - slot
 &xor($tmp1,$d);			# F2
&mov(&swtmp($n0),$f);			# X9 - anytime
 &and($tmp1,$b);			# F3
&lea($f,&DWP($K,$f,$e,1));		# tot=X+K+e
 &xor($tmp1,$d);				# F4
&mov($e,$a);				# A1
 &add($f,$tmp1);			# tot+=F();

&rotl($e,5);				# A2

&rotr($b,1);				# B1	<- F
 &add($f,$e);				# tot+=a

############################
#	&BODY_40_59( 0,$K[2],$X,42,$A,$B,$C,$D,$E,$T);
#	&BODY_40_59( 0,$K[2],$X,43,$T,$A,$B,$C,$D,$E);
$n++;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);
	($b,$c,$d,$e,$f,$a)=($a,$b,$c,$d,$e,$f);


&mov($f,&swtmp($n0));			# X1
 &mov($tmp1,&swtmp($n1));		# X2
&xor($f,$tmp1);				# X3
 &mov($tmp1,&swtmp($n2));		# X4
&xor($f,$tmp1);				# X5
 &mov($tmp1,&swtmp($n3));		# X6
&rotr($c,1); #&rotr($b,1);		# B1	<- F # MOVED DOWN
 &xor($f,$tmp1);				# X7 - slot
&rotl($f,1);				# X8 - slot
 &mov($tmp1,$c);			# F1
&xor($tmp1,$d);			# F2
 &mov(&swtmp($n0),$f);			# X9 - anytime
&and($tmp1,$b);			# F3
 &lea($f,&DWP($K,$f,$e,1));		# tot=X+K+e

&xor($tmp1,$d);				# F4
 &mov($e,$a);				# A1

&rotl($e,5);				# A2

&rotr($b,1);				# B1	<- F
 &add($f,$e);				# tot+=a

&rotr($b,1);				# B1	<- F
 &add($f,$tmp1);			# tot+=F();

	}

sub BODY_20_39
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;

	&comment("20_39 $n");
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

&mov($f,&swtmp($n0));			# X1
 &mov($tmp1,&swtmp($n1));		# X2
&xor($f,$tmp1);				# X3
 &mov($tmp1,&swtmp($n2));		# X4
&xor($f,$tmp1);				# X5
 &mov($tmp1,&swtmp($n3));		# X6
&xor($f,$tmp1);				# X7 - slot
 &mov($tmp1,$b);			# F1
&rotl($f,1);				# X8 - slot
 &xor($tmp1,$c);			# F2
&mov(&swtmp($n0),$f);			# X9 - anytime
 &xor($tmp1,$d);			# F3

&lea($f,&DWP($K,$f,$e,1));		# tot=X+K+e
 &mov($e,$a);				# A1

&rotl($e,5);				# A2

if ($n != 79) # last loop	
	{
	&rotr($b,1);				# B1	<- F
	 &add($e,$tmp1);			# tmp1=F()+a

	&rotr($b,1);				# B2	<- F
	 &add($f,$e);				# tot+=tmp1;
	}
else
	{
	&add($e,$tmp1);				# tmp1=F()+a
	 &mov($tmp1,&wparam(0));

	&rotr($b,1);				# B1	<- F
	 &add($f,$e);				# tot+=tmp1;

	&rotr($b,1);				# B2	<- F
	}
	}

sub BODY_40_59
	{
	local($pos,$K,$X,$n,$a,$b,$c,$d,$e,$f)=@_;

	&comment("40_59 $n");
	return if $n & 1;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);

&mov($f,&swtmp($n0));			# X1
 &mov($tmp1,&swtmp($n1));		# X2
&xor($f,$tmp1);				# X3
 &mov($tmp1,&swtmp($n2));		# X4
&xor($f,$tmp1);				# X5
 &mov($tmp1,&swtmp($n3));		# X6
&xor($f,$tmp1);				# X7 - slot
 &mov($tmp1,$b);			# F1
&rotl($f,1);				# X8 - slot
 &or($tmp1,$c);				# F2
&mov(&swtmp($n0),$f);			# X9 - anytime
 &and($tmp1,$d);			# F3

&lea($f,&DWP($K,$f,$e,1));		# tot=X+K+e
 &mov($e,$b);				# F4

&rotr($b,1);				# B1	<- F
 &and($e,$c);				# F5

&or($tmp1,$e);				# F6
 &mov($e,$a);				# A1

&rotl($e,5);				# A2

&add($tmp1,$e);			# tmp1=F()+a

############################
#	&BODY_40_59( 0,$K[2],$X,42,$A,$B,$C,$D,$E,$T);
#	&BODY_40_59( 0,$K[2],$X,43,$T,$A,$B,$C,$D,$E);
$n++;
	local($n0,$n1,$n2,$n3,$np)=&Na($n);
	($b,$c,$d,$e,$f,$a)=($a,$b,$c,$d,$e,$f);

 &mov($f,&swtmp($n0));			# X1
&add($a,$tmp1);				# tot+=tmp1; # moved was add f,tmp1
 &mov($tmp1,&swtmp($n1));		# X2
&xor($f,$tmp1);				# X3
 &mov($tmp1,&swtmp($n2));		# X4
&xor($f,$tmp1);				# X5
 &mov($tmp1,&swtmp($n3));		# X6
&rotr($c,1);				# B2	<- F # moved was rotr b,1
 &xor($f,$tmp1);			# X7 - slot
&rotl($f,1);				# X8 - slot
 &mov($tmp1,$b);			# F1
&mov(&swtmp($n0),$f);			# X9 - anytime
 &or($tmp1,$c);				# F2
&lea($f,&DWP($K,$f,$e,1));		# tot=X+K+e
 &mov($e,$b);				# F4
&and($tmp1,$d);				# F3
 &and($e,$c);				# F5

&or($tmp1,$e);				# F6
 &mov($e,$a);				# A1

&rotl($e,5);				# A2

&rotr($b,1);				# B1	<- F
 &add($tmp1,$e);			# tmp1=F()+a

&rotr($b,1);				# B2	<- F
 &add($f,$tmp1);			# tot+=tmp1;
	}

sub BODY_60_79
	{
	&BODY_20_39(@_);
	}

sub sha1_block
	{
	local($name)=@_;

	&function_begin_B($name,"");

	# parameter 1 is the MD5_CTX structure.
	# A	0
	# B	4
	# C	8
	# D 	12
	# E 	16

	&push("esi");
	 &push("ebp");
	&mov("eax",	&wparam(2));
	 &mov("esi",	&wparam(1));
	&add("eax",	"esi");	# offset to leave on
	 &mov("ebp",	&wparam(0));
	&push("ebx");
	 &sub("eax",	64);
	&push("edi");
	 &mov($B,	&DWP( 4,"ebp","",0));
	&stack_push(18);
	 &mov($D,	&DWP(12,"ebp","",0));
	&mov($E,	&DWP(16,"ebp","",0));
	 &mov($C,	&DWP( 8,"ebp","",0));
	&mov(&swtmp(17),"eax");

	&comment("First we need to setup the X array");
	 &mov("eax",&DWP(0,"esi","",0)); # pulled out of X_expand

	&set_label("start") unless $normal;

	&X_expand("esi");
	 &mov(&swtmp(16),"esi");

	&comment("");
	&comment("Start processing");

	# odd start
	&mov($A,	&DWP( 0,"ebp","",0));
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

	# The last 2 have been moved into the last loop
	# &mov($tmp1,&wparam(0));

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
	&mov("esi",&swtmp(16));
	 &mov(&DWP( 8,$tmp1,"",0),$C);	# This is for looping
 	&add("esi",64);
	 &mov("eax",&swtmp(17));
	&mov(&DWP(16,$tmp1,"",0),$E);
	 &cmp("eax","esi");
	&mov(&DWP( 4,$tmp1,"",0),$B);	# This is for looping
	 &jl(&label("end"));
	&mov("eax",&DWP(0,"esi","",0));	# Pulled down from 
	 &jmp(&label("start"));

	&set_label("end");
	&stack_pop(18);
	 &pop("edi");
	&pop("ebx");
	 &pop("ebp");
	&pop("esi");
	 &ret();
	&function_end_B($name);
	}

