#!/usr/local/bin/perl
# alpha assember 

sub bn_mul_words
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

	($a0)=&NR(1); &ld($a0,&QWPw(0,$ap));

	&set_label("loop");

	($a1)=&NR(1); &ld($a1,&QWPw(1,$ap));
	 ($a2)=&NR(1); &ld($a2,&QWPw(2,$ap));

	&muh($a0,$word,($h0)=&NR(1));	&FR($a0);
	 ($a3)=&NR(1); &ld($a3,&QWPw(3,$ap));
	 						### wait 8
	&mul($a0,$word,($l0)=&NR(1));	&FR($a0);
	 						### wait 8
	&muh($a1,$word,($h1)=&NR(1));	&FR($a1);
	 &add($l0,$cc,$l0);				### wait 8
	&mul($a1,$word,($l1)=&NR(1));	&FR($a1);
	 &cmpult($l0,$cc,$cc);				### wait 8
	&muh($a2,$word,($h2)=&NR(1));	&FR($a2);
	 &add($h0,$cc,$cc);	&FR($h0); 		### wait 8
	&mul($a2,$word,($l2)=&NR(1));	&FR($a2);
	 &add($l1,$cc,$l1);				### wait 8
	&st($l0,&QWPw(0,$rp));		&FR($l0);
	 &cmpult($l1,$cc,$cc);				### wait 8
	&muh($a3,$word,($h3)=&NR(1));	&FR($a3);
	 &add($h1,$cc,$cc);		&FR($h1);
	&mul($a3,$word,($l3)=&NR(1));	&FR($a3);
	 &add($l2,$cc,$l2);
	&st($l1,&QWPw(1,$rp));		&FR($l1);
	 &cmpult($l2,$cc,$cc);
	&add($h2,$cc,$cc);		&FR($h2);
	 &sub($count,4,$count);	# count-=4
	&st($l2,&QWPw(2,$rp));		&FR($l2);
	 &add($l3,$cc,$l3);
	&cmpult($l3,$cc,$cc);
	 &add($bp,4*$QWS,$bp);	# count+=4
	&add($h3,$cc,$cc);		&FR($h3);
	 &add($ap,4*$QWS,$ap);	# count+=4
	&st($l3,&QWPw(3,$rp));		&FR($l3);
	 &add($rp,4*$QWS,$rp);	# count+=4
	###
	 &blt($count,&label("finish"));
	 ($a0)=&NR(1); &ld($a0,&QWPw(0,$ap));
	&br(&label("finish"));
##################################################

##################################################
	# Do the last 0..3 words

	&set_label("last_loop");

	&ld(($a0)=&NR(1),&QWPw(0,$ap));	# get a
	 ###
	###
	 ###
	&muh($a0,$word,($h0)=&NR(1));
	 ### Wait 8 for next mul issue
	&mul($a0,$word,($l0)=&NR(1)); &FR($a0)
	 &add($ap,$QWS,$ap);
	### Loose 12 until result is available
	&add($rp,$QWS,$rp);
	 &sub($count,1,$count);
	&add($l0,$cc,$l0);
	 ###
	&st($l0,&QWPw(-1,$rp));		&FR($l0);
	 &cmpult($l0,$cc,$cc);
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
