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
	&br(&label("finish"));
	&blt($count,&label("finish"));

	($a0,$r0)=&NR(2);
	&ld($a0,&QWPw(0,$ap));
	&ld($r0,&QWPw(0,$rp));

$a=<<'EOF';
##########################################################
	&set_label("loop");

	($a1)=&NR(1); &ld($a1,&QWPw(1,$ap));
	($b1)=&NR(1); &ld($b1,&QWPw(1,$bp));
	($a2)=&NR(1); &ld($a2,&QWPw(2,$ap));
	($b2)=&NR(1); &ld($b2,&QWPw(2,$bp));
	($a3)=&NR(1); &ld($a3,&QWPw(3,$ap));
	($b3)=&NR(1); &ld($b3,&QWPw(3,$bp));

	($o0,$t0)=&NR(2);
	&add($a0,$b0,$o0); 
	&cmpult($o0,$b0,$t0);
	&add($o0,$cc,$o0);
	&cmpult($o0,$cc,$cc);
	&add($cc,$t0,$cc);	&FR($t0);

	($t1,$o1)=&NR(2);

	&add($a1,$b1,$o1);	&FR($a1);
	&cmpult($o1,$b1,$t1);	&FR($b1);
	&add($o1,$cc,$o1);
	&cmpult($o1,$cc,$cc);
	&add($cc,$t1,$cc);	&FR($t1);

	($t2,$o2)=&NR(2);

	&add($a2,$b2,$o2);	&FR($a2);
	&cmpult($o2,$b2,$t2);	&FR($b2);
	&add($o2,$cc,$o2);
	&cmpult($o2,$cc,$cc);
	&add($cc,$t2,$cc);	&FR($t2);

	($t3,$o3)=&NR(2);

	&add($a3,$b3,$o3);	&FR($a3);
	&cmpult($o3,$b3,$t3);	&FR($b3);
	&add($o3,$cc,$o3);
	&cmpult($o3,$cc,$cc);
	&add($cc,$t3,$cc);	&FR($t3);

	&st($o0,&QWPw(0,$rp)); &FR($o0);
	&st($o1,&QWPw(0,$rp)); &FR($o1);
	&st($o2,&QWPw(0,$rp)); &FR($o2);
	&st($o3,&QWPw(0,$rp)); &FR($o3);

	&sub($count,4,$count);	# count-=4
	&add($ap,4*$QWS,$ap);	# count+=4
	&add($bp,4*$QWS,$bp);	# count+=4
	&add($rp,4*$QWS,$rp);	# count+=4

	&blt($count,&label("finish"));
	&ld($a0,&QWPw(0,$ap));
	 &ld($b0,&QWPw(0,$bp));
	&br(&label("loop"));
EOF
##################################################
	# Do the last 0..3 words

	&set_label("last_loop");

	&ld(($a0)=&NR(1),&QWPw(0,$ap));	# get a
	&ld(($r0)=&NR(1),&QWPw(0,$rp));	# get b
	&mul($a0,$word,($l0)=&NR(1));
	 &sub($count,1,$count);
	 &add($ap,$QWS,$ap);
	&muh($a0,$word,($h0)=&NR(1));	&FR($a0);
	&add($r0,$l0,$r0);
	 &add($rp,$QWS,$rp);
	&cmpult($r0,$l0,($t0)=&NR(1));	&FR($l0);
	 &add($r0,$cc,$r0);
	&add($h0,$t0,$h0);		&FR($t0);
	 &cmpult($r0,$cc,$cc);
	&st($r0,&QWPw(-1,$rp));		&FR($r0);
	 &add($h0,$cc,$cc);		&FR($h0);

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
