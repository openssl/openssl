#!/usr/local/bin/perl
# alpha assember 

sub bn_mul_add_words
	{
	local($name)=@_;
	local($cc,$a,$b,$r,$couny);

	&init_pool(4);
	($cc)=GR("r0");

	$rp=&wparam(0);
	$ap=&wparam(1);
	$count=&wparam(2);
	$word=&wparam(3);

	&function_begin($name,"");

	&comment("");
	&sub($count,4,$count);
	 &mov("zero",$cc);
	###
	 &blt($count,&label("finish"));

	&ld(($a0)=&NR(1),&QWPw(0,$ap));

$a=<<'EOF';
##########################################################
	&set_label("loop");

	&ld(($r0)=&NR(1),&QWPw(0,$rp));
	 &ld(($a1)=&NR(1),&QWPw(1,$ap));
	&muh($a0,$word,($h0)=&NR(1));
	 &ld(($r1)=&NR(1),&QWPw(1,$rp));
	&ld(($a2)=&NR(1),&QWPw(2,$ap));
	 ###
	&mul($a0,$word,($l0)=&NR(1));	&FR($a0);
	 &ld(($r2)=&NR(1),&QWPw(2,$rp));
	&muh($a1,$word,($h1)=&NR(1));
	 &ld(($a3)=&NR(1),&QWPw(3,$ap));
	&mul($a1,$word,($l1)=&NR(1));	&FR($a1);
	 &ld(($r3)=&NR(1),&QWPw(3,$rp));
	&add($r0,$l0,$r0);
	 &add($r1,$l1,$r1);
	&cmpult($r0,$l0,($t0)=&NR(1));	&FR($l0);
	 &cmpult($r1,$l1,($t1)=&NR(1));	&FR($l1);
	&muh($a2,$word,($h2)=&NR(1));
	 &add($r0,$cc,$r0);
	&add($h0,$t0,$h0);		&FR($t0);
	 &cmpult($r0,$cc,$cc);
	&add($h1,$t1,$h1);		&FR($t1);
	 &add($h0,$cc,$cc);		&FR($h0);
	&mul($a2,$word,($l2)=&NR(1));	&FR($a2);
	 &add($r1,$cc,$r1);
	&cmpult($r1,$cc,$cc);
	 &add($r2,$l2,$r2);
	&add($h1,$cc,$cc);		&FR($h1);
	 &cmpult($r2,$l2,($t2)=&NR(1));	&FR($l2);
	&muh($a3,$word,($h3)=&NR(1));
	 &add($r2,$cc,$r2);
	&st($r0,&QWPw(0,$rp)); &FR($r0);
	 &add($h2,$t2,$h2);		&FR($t2);
	&st($r1,&QWPw(1,$rp)); &FR($r1);
	 &cmpult($r2,$cc,$cc);
	&mul($a3,$word,($l3)=&NR(1));	&FR($a3);
	 &add($h2,$cc,$cc);		&FR($h2);
	&st($r2,&QWPw(2,$rp)); &FR($r2);
	 &sub($count,4,$count);	# count-=4
	 &add($rp,4*$QWS,$rp);	# count+=4
	&add($r3,$l3,$r3);
	 &add($ap,4*$QWS,$ap);	# count+=4
	&cmpult($r3,$l3,($t3)=&NR(1));	&FR($l3);
	 &add($r3,$cc,$r3);
	&add($h3,$t3,$h3);		&FR($t3);
	 &cmpult($r3,$cc,$cc);
	&st($r3,&QWPw(-1,$rp)); &FR($r3);
	 &add($h3,$cc,$cc);		&FR($h3);

	###
	 &blt($count,&label("finish"));
	&ld(($a0)=&NR(1),&QWPw(0,$ap));
	 &br(&label("loop"));
EOF
##################################################
	# Do the last 0..3 words

	&set_label("last_loop");

	&ld(($a0)=&NR(1),&QWPw(0,$ap));	# get a
	 &ld(($r0)=&NR(1),&QWPw(0,$rp));	# get b
	###
	 ###
	&muh($a0,$word,($h0)=&NR(1));	&FR($a0);
	 ### wait 8
	&mul($a0,$word,($l0)=&NR(1));	&FR($a0);
	 &add($rp,$QWS,$rp);
	&add($ap,$QWS,$ap);
	 &sub($count,1,$count);
	### wait 3 until l0 is available
	&add($r0,$l0,$r0);
	 ###
	&cmpult($r0,$l0,($t0)=&NR(1));	&FR($l0);
	 &add($r0,$cc,$r0);
	&add($h0,$t0,$h0);		&FR($t0);
	 &cmpult($r0,$cc,$cc);
	&add($h0,$cc,$cc);		&FR($h0);

	&st($r0,&QWPw(-1,$rp));		&FR($r0);
	 &bgt($count,&label("last_loop"));
	&function_end_A($name);

######################################################
	&set_label("finish");
	&add($count,4,$count);
	 &bgt($count,&label("last_loop"));

	&set_label("end");
	&function_end($name);

	&fin_pool;
	}

1;
