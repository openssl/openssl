#!/usr/local/bin/perl
# alpha assember 

sub bn_add_words
	{
	local($name)=@_;
	local($cc,$a,$b,$r);

	&init_pool(4);
	($cc)=GR("r0");

	$rp=&wparam(0);
	$ap=&wparam(1);
	$bp=&wparam(2);
	$count=&wparam(3);

	&function_begin($name,"");

	&comment("");
	&sub($count,4,$count);
	 &mov("zero",$cc);
	&blt($count,&label("finish"));

	($a0,$b0)=&NR(2);

##########################################################
	&set_label("loop");

	&ld(($a0)=&NR(1),&QWPw(0,$ap));
	 &ld(($b0)=&NR(1),&QWPw(0,$bp));
	&ld(($a1)=&NR(1),&QWPw(1,$ap));
	 &ld(($b1)=&NR(1),&QWPw(1,$bp));

	($o0,$t0)=&NR(2);
	&add($a0,$b0,$o0); 
	 &ld(($a2)=&NR(1),&QWPw(2,$ap));
	&cmpult($o0,$b0,$t0);
	 &add($o0,$cc,$o0);
	&cmpult($o0,$cc,$cc);
	 &ld(($b2)=&NR(1),&QWPw(2,$bp));
	&add($cc,$t0,$cc);	&FR($t0);

	($t1,$o1)=&NR(2);

	 &add($a1,$b1,$o1);	&FR($a1);
	&cmpult($o1,$b1,$t1);	&FR($b1);
	 &add($o1,$cc,$o1);
	&cmpult($o1,$cc,$cc);
	 &ld(($a3)=&NR(1),&QWPw(3,$ap));
	&add($cc,$t1,$cc);	&FR($t1);

	($t2,$o2)=&NR(2);

	 &add($a2,$b2,$o2);	&FR($a2);
	&cmpult($o2,$b2,$t2);	&FR($b2);
	 &add($o2,$cc,$o2);
	&cmpult($o2,$cc,$cc);
	 &ld(($b3)=&NR(1),&QWPw(3,$bp));
	&st($o0,&QWPw(0,$rp)); &FR($o0);
	 &add($cc,$t2,$cc);	&FR($t2);

	($t3,$o3)=&NR(2);

	&st($o1,&QWPw(0,$rp)); &FR($o1);
	 &add($a3,$b3,$o3);	&FR($a3);
	&cmpult($o3,$b3,$t3);	&FR($b3);
	 &add($o3,$cc,$o3);
	&st($o2,&QWPw(0,$rp)); &FR($o2);
	 &cmpult($o3,$cc,$cc);
	&st($o3,&QWPw(0,$rp)); &FR($o3);
	 &add($cc,$t3,$cc);	&FR($t3);


	&sub($count,4,$count);	# count-=4
	 &add($ap,4*$QWS,$ap);	# count+=4
	&add($bp,4*$QWS,$bp);	# count+=4
	 &add($rp,4*$QWS,$rp);	# count+=4

	###
	 &bge($count,&label("loop"));
	###
	&br(&label("finish"));
##################################################
	# Do the last 0..3 words

	($t0,$o0)=&NR(2);
	&set_label("last_loop");

	&ld($a0,&QWPw(0,$ap));	# get a
	 &ld($b0,&QWPw(0,$bp));	# get b
	&add($ap,$QWS,$ap);
	 &add($bp,$QWS,$bp);
	&add($a0,$b0,$o0); 
	 &sub($count,1,$count);
	&cmpult($o0,$b0,$t0);	# will we borrow?
	 &add($o0,$cc,$o0);	# will we borrow?
	&cmpult($o0,$cc,$cc);	# will we borrow?
	 &add($rp,$QWS,$rp);
	&st($o0,&QWPw(-1,$rp));	# save
	 &add($cc,$t0,$cc);	# add the borrows

	###
	 &bgt($count,&label("last_loop"));
	&function_end_A($name);

######################################################
	&set_label("finish");
	&add($count,4,$count);
	 &bgt($count,&label("last_loop"));

	&FR($o0,$t0,$a0,$b0);
	&set_label("end");
	&function_end($name);

	&fin_pool;
	}

1;
