#!/usr/local/bin/perl

push(@INC,"perlasm","../../perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

&bn_mul_add_words("bn_mul_add_words");
&bn_mul_words("bn_mul_words");
&bn_sqr_words("bn_sqr_words");
&bn_div_words("bn_div_words");
&bn_add_words("bn_add_words");
&bn_sub_words("bn_sub_words");
&bn_sub_part_words("bn_sub_part_words");

&asm_finish();

sub bn_mul_add_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$Low="eax";
	$High="edx";
	$a="ebx";
	$w="ebp";
	$r="edi";
	$c="esi";

	&xor($c,$c);		# clear carry
	&mov($r,&wparam(0));	#

	&mov("ecx",&wparam(2));	#
	&mov($a,&wparam(1));	#

	&and("ecx",0xfffffff8);	# num / 8
	&mov($w,&wparam(3));	#

	&push("ecx");		# Up the stack for a tmp variable

	&jz(&label("maw_finish"));

	&set_label("maw_loop",0);

	&mov(&swtmp(0),"ecx");	#

	for ($i=0; $i<32; $i+=4)
		{
		&comment("Round $i");

		 &mov("eax",&DWP($i,$a,"",0)); 	# *a
		&mul($w);			# *a * w
		&add("eax",$c);		# L(t)+= *r
		 &mov($c,&DWP($i,$r,"",0));	# L(t)+= *r
		&adc("edx",0);			# H(t)+=carry
		 &add("eax",$c);		# L(t)+=c
		&adc("edx",0);			# H(t)+=carry
		 &mov(&DWP($i,$r,"",0),"eax");	# *r= L(t);
		&mov($c,"edx");			# c=  H(t);
		}

	&comment("");
	&mov("ecx",&swtmp(0));	#
	&add($a,32);
	&add($r,32);
	&sub("ecx",8);
	&jnz(&label("maw_loop"));

	&set_label("maw_finish",0);
	&mov("ecx",&wparam(2));	# get num
	&and("ecx",7);
	&jnz(&label("maw_finish2"));	# helps branch prediction
	&jmp(&label("maw_end"));

	&set_label("maw_finish2",1);
	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		 &mov("eax",&DWP($i*4,$a,"",0));# *a
		&mul($w);			# *a * w
		&add("eax",$c);			# L(t)+=c
		 &mov($c,&DWP($i*4,$r,"",0));	# L(t)+= *r
		&adc("edx",0);			# H(t)+=carry
		 &add("eax",$c);
		&adc("edx",0);			# H(t)+=carry
		 &dec("ecx") if ($i != 7-1);
		&mov(&DWP($i*4,$r,"",0),"eax");	# *r= L(t);
		 &mov($c,"edx");			# c=  H(t);
		&jz(&label("maw_end")) if ($i != 7-1);
		}
	&set_label("maw_end",0);
	&mov("eax",$c);

	&pop("ecx");	# clear variable from

	&function_end($name);
	}

sub bn_mul_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$Low="eax";
	$High="edx";
	$a="ebx";
	$w="ecx";
	$r="edi";
	$c="esi";
	$num="ebp";

	&xor($c,$c);		# clear carry
	&mov($r,&wparam(0));	#
	&mov($a,&wparam(1));	#
	&mov($num,&wparam(2));	#
	&mov($w,&wparam(3));	#

	&and($num,0xfffffff8);	# num / 8
	&jz(&label("mw_finish"));

	&set_label("mw_loop",0);
	for ($i=0; $i<32; $i+=4)
		{
		&comment("Round $i");

		 &mov("eax",&DWP($i,$a,"",0)); 	# *a
		&mul($w);			# *a * w
		&add("eax",$c);			# L(t)+=c
		 # XXX

		&adc("edx",0);			# H(t)+=carry
		 &mov(&DWP($i,$r,"",0),"eax");	# *r= L(t);

		&mov($c,"edx");			# c=  H(t);
		}

	&comment("");
	&add($a,32);
	&add($r,32);
	&sub($num,8);
	&jz(&label("mw_finish"));
	&jmp(&label("mw_loop"));

	&set_label("mw_finish",0);
	&mov($num,&wparam(2));	# get num
	&and($num,7);
	&jnz(&label("mw_finish2"));
	&jmp(&label("mw_end"));

	&set_label("mw_finish2",1);
	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		 &mov("eax",&DWP($i*4,$a,"",0));# *a
		&mul($w);			# *a * w
		&add("eax",$c);			# L(t)+=c
		 # XXX
		&adc("edx",0);			# H(t)+=carry
		 &mov(&DWP($i*4,$r,"",0),"eax");# *r= L(t);
		&mov($c,"edx");			# c=  H(t);
		 &dec($num) if ($i != 7-1);
		&jz(&label("mw_end")) if ($i != 7-1);
		}
	&set_label("mw_end",0);
	&mov("eax",$c);

	&function_end($name);
	}

sub bn_sqr_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$r="esi";
	$a="edi";
	$num="ebx";

	&mov($r,&wparam(0));	#
	&mov($a,&wparam(1));	#
	&mov($num,&wparam(2));	#

	&and($num,0xfffffff8);	# num / 8
	&jz(&label("sw_finish"));

	&set_label("sw_loop",0);
	for ($i=0; $i<32; $i+=4)
		{
		&comment("Round $i");
		&mov("eax",&DWP($i,$a,"",0)); 	# *a
		 # XXX
		&mul("eax");			# *a * *a
		&mov(&DWP($i*2,$r,"",0),"eax");	#
		 &mov(&DWP($i*2+4,$r,"",0),"edx");#
		}

	&comment("");
	&add($a,32);
	&add($r,64);
	&sub($num,8);
	&jnz(&label("sw_loop"));

	&set_label("sw_finish",0);
	&mov($num,&wparam(2));	# get num
	&and($num,7);
	&jz(&label("sw_end"));

	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		&mov("eax",&DWP($i*4,$a,"",0));	# *a
		 # XXX
		&mul("eax");			# *a * *a
		&mov(&DWP($i*8,$r,"",0),"eax");	#
		 &dec($num) if ($i != 7-1);
		&mov(&DWP($i*8+4,$r,"",0),"edx");
		 &jz(&label("sw_end")) if ($i != 7-1);
		}
	&set_label("sw_end",0);

	&function_end($name);
	}

sub bn_div_words
	{
	local($name)=@_;

	&function_begin($name,"");
	&mov("edx",&wparam(0));	#
	&mov("eax",&wparam(1));	#
	&mov("ebx",&wparam(2));	#
	&div("ebx");
	&function_end($name);
	}

sub bn_add_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$a="esi";
	$b="edi";
	$c="eax";
	$r="ebx";
	$tmp1="ecx";
	$tmp2="edx";
	$num="ebp";

	&mov($r,&wparam(0));	# get r
	 &mov($a,&wparam(1));	# get a
	&mov($b,&wparam(2));	# get b
	 &mov($num,&wparam(3));	# get num
	&xor($c,$c);		# clear carry
	 &and($num,0xfffffff8);	# num / 8

	&jz(&label("aw_finish"));

	&set_label("aw_loop",0);
	for ($i=0; $i<8; $i++)
		{
		&comment("Round $i");

		&mov($tmp1,&DWP($i*4,$a,"",0)); 	# *a
		 &mov($tmp2,&DWP($i*4,$b,"",0)); 	# *b
		&add($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &add($tmp1,$tmp2);
		&adc($c,0);
		 &mov(&DWP($i*4,$r,"",0),$tmp1); 	# *r
		}

	&comment("");
	&add($a,32);
	 &add($b,32);
	&add($r,32);
	 &sub($num,8);
	&jnz(&label("aw_loop"));

	&set_label("aw_finish",0);
	&mov($num,&wparam(3));	# get num
	&and($num,7);
	 &jz(&label("aw_end"));

	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		&mov($tmp1,&DWP($i*4,$a,"",0));	# *a
		 &mov($tmp2,&DWP($i*4,$b,"",0));# *b
		&add($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &add($tmp1,$tmp2);
		&adc($c,0);
		 &dec($num) if ($i != 6);
		&mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
		 &jz(&label("aw_end")) if ($i != 6);
		}
	&set_label("aw_end",0);

#	&mov("eax",$c);		# $c is "eax"

	&function_end($name);
	}

sub bn_sub_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$a="esi";
	$b="edi";
	$c="eax";
	$r="ebx";
	$tmp1="ecx";
	$tmp2="edx";
	$num="ebp";

	&mov($r,&wparam(0));	# get r
	 &mov($a,&wparam(1));	# get a
	&mov($b,&wparam(2));	# get b
	 &mov($num,&wparam(3));	# get num
	&xor($c,$c);		# clear carry
	 &and($num,0xfffffff8);	# num / 8

	&jz(&label("aw_finish"));

	&set_label("aw_loop",0);
	for ($i=0; $i<8; $i++)
		{
		&comment("Round $i");

		&mov($tmp1,&DWP($i*4,$a,"",0)); 	# *a
		 &mov($tmp2,&DWP($i*4,$b,"",0)); 	# *b
		&sub($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &sub($tmp1,$tmp2);
		&adc($c,0);
		 &mov(&DWP($i*4,$r,"",0),$tmp1); 	# *r
		}

	&comment("");
	&add($a,32);
	 &add($b,32);
	&add($r,32);
	 &sub($num,8);
	&jnz(&label("aw_loop"));

	&set_label("aw_finish",0);
	&mov($num,&wparam(3));	# get num
	&and($num,7);
	 &jz(&label("aw_end"));

	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		&mov($tmp1,&DWP($i*4,$a,"",0));	# *a
		 &mov($tmp2,&DWP($i*4,$b,"",0));# *b
		&sub($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &sub($tmp1,$tmp2);
		&adc($c,0);
		 &dec($num) if ($i != 6);
		&mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
		 &jz(&label("aw_end")) if ($i != 6);
		}
	&set_label("aw_end",0);

#	&mov("eax",$c);		# $c is "eax"

	&function_end($name);
	}

sub bn_sub_part_words
	{
	local($name)=@_;

	&function_begin($name,"");

	&comment("");
	$a="esi";
	$b="edi";
	$c="eax";
	$r="ebx";
	$tmp1="ecx";
	$tmp2="edx";
	$num="ebp";

	&mov($r,&wparam(0));	# get r
	 &mov($a,&wparam(1));	# get a
	&mov($b,&wparam(2));	# get b
	 &mov($num,&wparam(3));	# get num
	&xor($c,$c);		# clear carry
	 &and($num,0xfffffff8);	# num / 8

	&jz(&label("aw_finish"));

	&set_label("aw_loop",0);
	for ($i=0; $i<8; $i++)
		{
		&comment("Round $i");

		&mov($tmp1,&DWP($i*4,$a,"",0)); 	# *a
		 &mov($tmp2,&DWP($i*4,$b,"",0)); 	# *b
		&sub($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &sub($tmp1,$tmp2);
		&adc($c,0);
		 &mov(&DWP($i*4,$r,"",0),$tmp1); 	# *r
		}

	&comment("");
	&add($a,32);
	 &add($b,32);
	&add($r,32);
	 &sub($num,8);
	&jnz(&label("aw_loop"));

	&set_label("aw_finish",0);
	&mov($num,&wparam(3));	# get num
	&and($num,7);
	 &jz(&label("aw_end"));

	for ($i=0; $i<7; $i++)
		{
		&comment("Tail Round $i");
		&mov($tmp1,&DWP(0,$a,"",0));	# *a
		 &mov($tmp2,&DWP(0,$b,"",0));# *b
		&sub($tmp1,$c);
		 &mov($c,0);
		&adc($c,$c);
		 &sub($tmp1,$tmp2);
		&adc($c,0);
		&mov(&DWP(0,$r,"",0),$tmp1);	# *r
		&add($a, 4);
		&add($b, 4);
		&add($r, 4);
		 &dec($num) if ($i != 6);
		 &jz(&label("aw_end")) if ($i != 6);
		}
	&set_label("aw_end",0);

	&cmp(&wparam(4),0);
	&je(&label("pw_end"));

	&mov($num,&wparam(4));	# get dl
	&cmp($num,0);
	&je(&label("pw_end"));
	&jge(&label("pw_pos"));

	&comment("pw_neg");
	&mov($tmp2,0);
	&sub($tmp2,$num);
	&mov($num,$tmp2);
	&and($num,0xfffffff8);	# num / 8
	&jz(&label("pw_neg_finish"));

	&set_label("pw_neg_loop",0);
	for ($i=0; $i<8; $i++)
	{
	    &comment("dl<0 Round $i");

	    &mov($tmp1,0);
	    &mov($tmp2,&DWP($i*4,$b,"",0)); 	# *b
	    &sub($tmp1,$c);
	    &mov($c,0);
	    &adc($c,$c);
	    &sub($tmp1,$tmp2);
	    &adc($c,0);
	    &mov(&DWP($i*4,$r,"",0),$tmp1); 	# *r
	}
	    
	&comment("");
	&add($b,32);
	&add($r,32);
	&sub($num,8);
	&jnz(&label("pw_neg_loop"));
	    
	&set_label("pw_neg_finish",0);
	&mov($tmp2,&wparam(4));	# get dl
	&mov($num,0);
	&sub($num,$tmp2);
	&and($num,7);
	&jz(&label("pw_end"));
	    
	for ($i=0; $i<7; $i++)
	{
	    &comment("dl<0 Tail Round $i");
	    &mov($tmp1,0);
	    &mov($tmp2,&DWP($i*4,$b,"",0));# *b
	    &sub($tmp1,$c);
	    &mov($c,0);
	    &adc($c,$c);
	    &sub($tmp1,$tmp2);
	    &adc($c,0);
	    &dec($num) if ($i != 6);
	    &mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
	    &jz(&label("pw_end")) if ($i != 6);
	}

	&jmp(&label("pw_end"));
	
	&set_label("pw_pos",0);
	
	&and($num,0xfffffff8);	# num / 8
	&jz(&label("pw_pos_finish"));

	&set_label("pw_pos_loop",0);

	for ($i=0; $i<8; $i++)
	{
	    &comment("dl>0 Round $i");

	    &mov($tmp1,&DWP($i*4,$a,"",0));	# *a
	    &sub($tmp1,$c);
	    &mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
	    &jnc(&label("pw_nc".$i));
	}
	    
	&comment("");
	&add($a,32);
	&add($r,32);
	&sub($num,8);
	&jnz(&label("pw_pos_loop"));
	    
	&set_label("pw_pos_finish",0);
	&mov($num,&wparam(4));	# get dl
	&and($num,7);
	&jz(&label("pw_end"));
	    
	for ($i=0; $i<7; $i++)
	{
	    &comment("dl>0 Tail Round $i");
	    &mov($tmp1,&DWP($i*4,$a,"",0));	# *a
	    &sub($tmp1,$c);
	    &mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
	    &jnc(&label("pw_tail_nc".$i));
	    &dec($num) if ($i != 6);
	    &jz(&label("pw_end")) if ($i != 6);
	}
	&mov($c,1);
	&jmp(&label("pw_end"));

	&set_label("pw_nc_loop",0);
	for ($i=0; $i<8; $i++)
	{
	    &mov($tmp1,&DWP($i*4,$a,"",0));	# *a
	    &mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
	    &set_label("pw_nc".$i,0);
	}
	    
	&comment("");
	&add($a,32);
	&add($r,32);
	&sub($num,8);
	&jnz(&label("pw_nc_loop"));
	    
	&mov($num,&wparam(4));	# get dl
	&and($num,7);
	&jz(&label("pw_nc_end"));
	    
	for ($i=0; $i<7; $i++)
	{
	    &mov($tmp1,&DWP($i*4,$a,"",0));	# *a
	    &mov(&DWP($i*4,$r,"",0),$tmp1);	# *r
	    &set_label("pw_tail_nc".$i,0);
	    &dec($num) if ($i != 6);
	    &jz(&label("pw_nc_end")) if ($i != 6);
	}

	&set_label("pw_nc_end",0);
	&mov($c,0);

	&set_label("pw_end",0);

#	&mov("eax",$c);		# $c is "eax"

	&function_end($name);
	}

