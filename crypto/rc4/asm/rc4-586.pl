#!/usr/local/bin/perl

# define for pentium pro friendly version

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"rc4-586.pl");

$tx="eax";
$ty="ebx";
$x="ecx";
$y="edx";
$in="esi";
$out="edi";
$d="ebp";

&RC4("RC4");

&asm_finish();

sub RC4_loop
	{
	local($n,$p,$char)=@_;

	&comment("Round $n");

	if ($char)
		{
		if ($p >= 0)
			{
			 &mov($ty,	&swtmp(2));
			&cmp($ty,	$in);
			 &jle(&label("finished"));
			&inc($in);
			}
		else
			{
			&add($ty,	8);
			 &inc($in);
			&cmp($ty,	$in);
			 &jl(&label("finished"));
			&mov(&swtmp(2),	$ty);
			}
		}
	# Moved out
	# &mov(	$tx,		&DWP(0,$d,$x,4)) if $p < 0;

	 &add(	$y,		$tx);
	&and(	$y,		0xff);
	 &inc(	$x);			# NEXT ROUND 
	&mov(	$ty,		&DWP(0,$d,$y,4));
	 # XXX
	&mov(	&DWP(-4,$d,$x,4),$ty);			# AGI
	 &add(	$ty,		$tx);
	&and(	$x,		0xff);	# NEXT ROUND
	 &and(	$ty,		0xff);
	&mov(	&DWP(0,$d,$y,4),$tx);
	 &nop();
	&mov(	$ty,		&DWP(0,$d,$ty,4));
	 &mov(	$tx,		&DWP(0,$d,$x,4)) if $p < 1; # NEXT ROUND
	 # XXX

	if (!$char)
		{
		#moved up into last round
		if ($p >= 1)
			{
			&add(	$out,	8)
			}
		&movb(	&BP($n,"esp","",0),	&LB($ty));
		}
	else
		{
		# Note in+=8 has occured
		&movb(	&HB($ty),	&BP(-1,$in,"",0));
		 # XXX
		&xorb(&LB($ty),		&HB($ty));
		 # XXX
		&movb(&BP($n,$out,"",0),&LB($ty));
		}
	}


sub RC4
	{
	local($name)=@_;

	&function_begin_B($name,"");

	&comment("");

	&push("ebp");
	 &push("ebx");
	&mov(	$d,	&wparam(0));	# key
	 &mov(	$ty,	&wparam(1));	# num
	&push("esi");
	 &push("edi");

	&mov(	$x,	&DWP(0,$d,"",1));
	 &mov(	$y,	&DWP(4,$d,"",1));

	&mov(	$in,	&wparam(2));
	 &inc(	$x);

	&stack_push(3);	# 3 temp variables
	 &add(	$d,	8);
	&and(	$x,		0xff);

	 &lea(	$ty,	&DWP(-8,$ty,$in));

	# check for 0 length input

	&mov(	$out,	&wparam(3));
	 &mov(	&swtmp(2),	$ty);	# this is now address to exit at
	&mov(	$tx,	&DWP(0,$d,$x,4));

	 &cmp(	$ty,	$in);
	&jl(	&label("end")); # less than 8 bytes

	&set_label("start");

	# filling DELAY SLOT
	&add(	$in,	8);

	&RC4_loop(0,-1,0);
	&RC4_loop(1,0,0);
	&RC4_loop(2,0,0);
	&RC4_loop(3,0,0);
	&RC4_loop(4,0,0);
	&RC4_loop(5,0,0);
	&RC4_loop(6,0,0);
	&RC4_loop(7,1,0);
	
	&comment("apply the cipher text");
	# xor the cipher data with input

	#&add(	$out,	8); #moved up into last round

	&mov(	$tx,	&swtmp(0));
	 &mov(	$ty,	&DWP(-8,$in,"",0));
	&xor(	$tx,	$ty);
	 &mov(	$ty,	&DWP(-4,$in,"",0)); 
	&mov(	&DWP(-8,$out,"",0),	$tx);
	 &mov(	$tx,	&swtmp(1));
	&xor(	$tx,	$ty);
	 &mov(	$ty,	&swtmp(2));	# load end ptr;
	&mov(	&DWP(-4,$out,"",0),	$tx);
	 &mov(	$tx,		&DWP(0,$d,$x,4));
	&cmp($in,	$ty);
	 &jle(&label("start"));

	&set_label("end");

	# There is quite a bit of extra crap in RC4_loop() for this
	# first round
	&RC4_loop(0,-1,1);
	&RC4_loop(1,0,1);
	&RC4_loop(2,0,1);
	&RC4_loop(3,0,1);
	&RC4_loop(4,0,1);
	&RC4_loop(5,0,1);
	&RC4_loop(6,1,1);

	&set_label("finished");
	&dec(	$x);
	 &stack_pop(3);
	&mov(	&DWP(-4,$d,"",0),$y);
	 &movb(	&BP(-8,$d,"",0),&LB($x));

	&function_end($name);
	}

