#!/usr/local/bin/perl
#
# The inner loop instruction sequence and the IP/FP modifications are from
# Svend Olaf Mikkelsen <svolaf@inet.uni-c.dk>
# I've added the stuff needed for crypt() but I've not worried about making
# things perfect.
#

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"crypt586.pl");

$L="edi";
$R="esi";

&external_label("des_SPtrans");
&fcrypt_body("fcrypt_body");
&asm_finish();

sub fcrypt_body
	{
	local($name,$do_ip)=@_;

	&function_begin($name,"EXTRN   _des_SPtrans:DWORD");

	&comment("");
	&comment("Load the 2 words");
	$ks="ebp";

	&xor(	$L,	$L);
	&xor(	$R,	$R);
	&mov($ks,&wparam(1));

	&push(&DWC(25)); # add a variable

	&set_label("start");
	for ($i=0; $i<16; $i+=2)
		{
		&comment("");
		&comment("Round $i");
		&D_ENCRYPT($i,$L,$R,$i*2,$ks,"des_SPtrans","eax","ebx","ecx","edx");

		&comment("");
		&comment("Round ".sprintf("%d",$i+1));
		&D_ENCRYPT($i+1,$R,$L,($i+1)*2,$ks,"des_SPtrans","eax","ebx","ecx","edx");
		}
	 &mov("ebx",	&swtmp(0));
	&mov("eax",	$L);
	 &dec("ebx");
	&mov($L,	$R);
	 &mov($R,	"eax");
	&mov(&swtmp(0),	"ebx");
	 &jnz(&label("start"));

	&comment("");
	&comment("FP");
	&mov("edx",&wparam(0));

	&FP_new($R,$L,"eax",3);
	&mov(&DWP(0,"edx","",0),"eax");
	&mov(&DWP(4,"edx","",0),$L);

	&pop("ecx");	# remove variable

	&function_end($name);
	}

sub D_ENCRYPT
	{
	local($r,$L,$R,$S,$ks,$desSP,$u,$tmp1,$tmp2,$t)=@_;

	&mov(	$u,		&wparam(2));			# 2
	&mov(	$t,		$R);
	&shr(	$t,		16);				# 1
	&mov(	$tmp2,		&wparam(3));			# 2
	&xor(	$t,		$R);				# 1

	&and(	$u,		$t);				# 2
	&and(	$t,		$tmp2);				# 2

	&mov(	$tmp1,		$u);
	&shl(	$tmp1,		16); 				# 1
	&mov(	$tmp2,		$t);
	&shl(	$tmp2,		16); 				# 1
	&xor(	$u,		$tmp1);				# 2
	&xor(	$t,		$tmp2);				# 2
	&mov(	$tmp1,		&DWP(&n2a($S*4),$ks,"",0));	# 2
	&xor(	$u,		$tmp1);
	&mov(	$tmp2,		&DWP(&n2a(($S+1)*4),$ks,"",0));	# 2
	&xor(	$u,		$R);
	&xor(	$t,		$R);
	&xor(	$t,		$tmp2);

	&and(	$u,		"0xfcfcfcfc"	);		# 2
	&xor(	$tmp1,		$tmp1);				# 1
	&and(	$t,		"0xcfcfcfcf"	);		# 2
	&xor(	$tmp2,		$tmp2);	
	&movb(	&LB($tmp1),	&LB($u)	);
	&movb(	&LB($tmp2),	&HB($u)	);
	&rotr(	$t,		4		);
	&mov(	$ks,		&DWP("      $desSP",$tmp1,"",0));
	&movb(	&LB($tmp1),	&LB($t)	);
	&xor(	$L,		$ks);
	&mov(	$ks,		&DWP("0x200+$desSP",$tmp2,"",0));
	&xor(	$L,		$ks);
	&movb(	&LB($tmp2),	&HB($t)	);
	&shr(	$u,		16);
	&mov(	$ks,		&DWP("0x100+$desSP",$tmp1,"",0));
	&xor(	$L,		$ks); 
	&movb(	&LB($tmp1),	&HB($u)	);
	&shr(	$t,		16);
	&mov(	$ks,		&DWP("0x300+$desSP",$tmp2,"",0));
	&xor(	$L,		$ks);
	&mov(	$ks,		&wparam(1));
	&movb(	&LB($tmp2),	&HB($t)	);
	&and(	$u,		"0xff"	);
	&and(	$t,		"0xff"	);
	&mov(	$tmp1,		&DWP("0x600+$desSP",$tmp1,"",0));
	&xor(	$L,		$tmp1);
	&mov(	$tmp1,		&DWP("0x700+$desSP",$tmp2,"",0));
	&xor(	$L,		$tmp1);
	&mov(	$tmp1,		&DWP("0x400+$desSP",$u,"",0));
	&xor(	$L,		$tmp1);
	&mov(	$tmp1,		&DWP("0x500+$desSP",$t,"",0));
	&xor(	$L,		$tmp1);
	}

sub n2a
	{
	sprintf("%d",$_[0]);
	}

# now has a side affect of rotating $a by $shift
sub R_PERM_OP
	{
	local($a,$b,$tt,$shift,$mask,$last)=@_;

	&rotl(	$a,		$shift		) if ($shift != 0);
	&mov(	$tt,		$a		);
	&xor(	$a,		$b		);
	&and(	$a,		$mask		);
	if ($notlast eq $b)
		{
		&xor(	$b,		$a		);
		&xor(	$tt,		$a		);
		}
	else
		{
		&xor(	$tt,		$a		);
		&xor(	$b,		$a		);
		}
	&comment("");
	}

sub IP_new
	{
	local($l,$r,$tt,$lr)=@_;

	&R_PERM_OP($l,$r,$tt, 4,"0xf0f0f0f0",$l);
	&R_PERM_OP($r,$tt,$l,20,"0xfff0000f",$l);
	&R_PERM_OP($l,$tt,$r,14,"0x33333333",$r);
	&R_PERM_OP($tt,$r,$l,22,"0x03fc03fc",$r);
	&R_PERM_OP($l,$r,$tt, 9,"0xaaaaaaaa",$r);
	
	if ($lr != 3)
		{
		if (($lr-3) < 0)
			{ &rotr($tt,	3-$lr); }
		else	{ &rotl($tt,	$lr-3); }
		}
	if ($lr != 2)
		{
		if (($lr-2) < 0)
			{ &rotr($r,	2-$lr); }
		else	{ &rotl($r,	$lr-2); }
		}
	}

sub FP_new
	{
	local($l,$r,$tt,$lr)=@_;

	if ($lr != 2)
		{
		if (($lr-2) < 0)
			{ &rotl($r,	2-$lr); }
		else	{ &rotr($r,	$lr-2); }
		}
	if ($lr != 3)
		{
		if (($lr-3) < 0)
			{ &rotl($l,	3-$lr); }
		else	{ &rotr($l,	$lr-3); }
		}

	&R_PERM_OP($l,$r,$tt, 0,"0xaaaaaaaa",$r);
	&R_PERM_OP($tt,$r,$l,23,"0x03fc03fc",$r);
	&R_PERM_OP($l,$r,$tt,10,"0x33333333",$l);
	&R_PERM_OP($r,$tt,$l,18,"0xfff0000f",$l);
	&R_PERM_OP($l,$tt,$r,12,"0xf0f0f0f0",$r);
	&rotr($tt	, 4);
	}

