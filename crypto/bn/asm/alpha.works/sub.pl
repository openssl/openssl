#!/usr/local/bin/perl
# alpha assember

sub bn_sub_words
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
	&ld($a0,&QWPw(0,$ap));
	&ld($b0,&QWPw(0,$bp));

##########################################################
	&set_label("loop");

	($a1,$tmp,$b1,$a2,$b2,$a3,$b3,$o0)=&NR(8);
	&ld($a1,&QWPw(1,$ap));
	 &cmpult($a0,$b0,$tmp);	# will we borrow?
	&ld($b1,&QWPw(1,$bp));
	 &sub($a0,$b0,$a0);		# do the subtract
	&ld($a2,&QWPw(2,$ap));
	 &cmpult($a0,$cc,$b0);	# will we borrow?
	&ld($b2,&QWPw(2,$bp));
	 &sub($a0,$cc,$o0);	# will we borrow?
	&ld($a3,&QWPw(3,$ap));
	 &add($b0,$tmp,$cc); ($t1,$o1)=&NR(2); &FR($tmp);

	&cmpult($a1,$b1,$t1);	# will we borrow?
	 &sub($a1,$b1,$a1);	# do the subtract
	&ld($b3,&QWPw(3,$bp));
	 &cmpult($a1,$cc,$b1);	# will we borrow?
	&sub($a1,$cc,$o1);	# will we borrow?
	 &add($b1,$t1,$cc); ($tmp,$o2)=&NR(2); &FR($t1,$a1,$b1);
	
	&cmpult($a2,$b2,$tmp);	# will we borrow?
	 &sub($a2,$b2,$a2);		# do the subtract
	&st($o0,&QWPw(0,$rp));	&FR($o0); # save
	 &cmpult($a2,$cc,$b2);	# will we borrow?
	&sub($a2,$cc,$o2);	# will we borrow?
	 &add($b2,$tmp,$cc); ($t3,$o3)=&NR(2); &FR($tmp,$a2,$b2);

	&cmpult($a3,$b3,$t3);	# will we borrow?
	 &sub($a3,$b3,$a3);	# do the subtract
	&st($o1,&QWPw(1,$rp)); &FR($o1);
	 &cmpult($a3,$cc,$b3);	# will we borrow?
	&sub($a3,$cc,$o3);	# will we borrow?
	 &add($b3,$t3,$cc); &FR($t3,$a3,$b3);

	&st($o2,&QWPw(2,$rp));	&FR($o2);
	 &sub($count,4,$count);	# count-=4
	&st($o3,&QWPw(3,$rp));	&FR($o3);
	 &add($ap,4*$QWS,$ap);	# count+=4
	&add($bp,4*$QWS,$bp);	# count+=4
	 &add($rp,4*$QWS,$rp);	# count+=4

	&blt($count,&label("finish"));
	&ld($a0,&QWPw(0,$ap));
	 &ld($b0,&QWPw(0,$bp));
	&br(&label("loop"));
##################################################
	# Do the last 0..3 words

	&set_label("last_loop");

	&ld($a0,&QWPw(0,$ap));	# get a
	 &ld($b0,&QWPw(0,$bp));	# get b
	&cmpult($a0,$b0,$tmp);	# will we borrow?
	&sub($a0,$b0,$a0);	# do the subtract
	&cmpult($a0,$cc,$b0);	# will we borrow?
	&sub($a0,$cc,$a0);	# will we borrow?
	&st($a0,&QWPw(0,$rp));	# save
	&add($b0,$tmp,$cc);	# add the borrows

	&add($ap,$QWS,$ap);
	&add($bp,$QWS,$bp);
	&add($rp,$QWS,$rp);
	&sub($count,1,$count);
	&bgt($count,&label("last_loop"));
	&function_end_A($name);

######################################################
	&set_label("finish");
	&add($count,4,$count);
	&bgt($count,&label("last_loop"));

	&FR($a0,$b0);
	&set_label("end");
	&function_end($name);

	&fin_pool;
	}

1;
