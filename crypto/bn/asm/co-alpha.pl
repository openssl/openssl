#!/usr/local/bin/perl
# I have this in perl so I can use more usefull register names and then convert
# them into alpha registers.
#

push(@INC,"perlasm","../../perlasm");
require "alpha.pl";

&asm_init($ARGV[0],$0);

print &bn_sub_words("bn_sub_words");

&asm_finish();

sub bn_sub_words
	{
	local($name)=@_;
	local($cc,$a,$b,$r);

	$cc="r0";
	$a0="r1"; $b0="r5"; $r0="r9";  $tmp="r13";
	$a1="r2"; $b1="r6"; $r1="r10"; $t1="r14";
	$a2="r3"; $b2="r7"; $r2="r11";
	$a3="r4"; $b3="r8"; $r3="r12"; $t3="r15";

	$rp=&wparam(0);
	$ap=&wparam(1);
	$bp=&wparam(2);
	$count=&wparam(3);

	&function_begin($name,"");

	&comment("");
	&sub($count,4,$count);
	&mov("zero",$cc);
	&blt($count,&label("finish"));

	&ld($a0,&QWPw(0,$ap));
	&ld($b0,&QWPw(0,$bp));

##########################################################
	&set_label("loop");

	&ld($a1,&QWPw(1,$ap));
	 &cmpult($a0,$b0,$tmp);	# will we borrow?
	&ld($b1,&QWPw(1,$bp));
	 &sub($a0,$b0,$a0);		# do the subtract
	&ld($a2,&QWPw(2,$ap));
	 &cmpult($a0,$cc,$b0);	# will we borrow?
	&ld($b2,&QWPw(2,$bp));
	 &sub($a0,$cc,$a0);	# will we borrow?
	&ld($a3,&QWPw(3,$ap));
	 &add($b0,$tmp,$cc);	# add the borrows

	&cmpult($a1,$b1,$t1);	# will we borrow?
	 &sub($a1,$b1,$a1);	# do the subtract
	&ld($b3,&QWPw(3,$bp));
	 &cmpult($a1,$cc,$b1);	# will we borrow?
	&sub($a1,$cc,$a1);	# will we borrow?
	 &add($b1,$t1,$cc);	# add the borrows

	&cmpult($a2,$b2,$tmp);	# will we borrow?
	 &sub($a2,$b2,$a2);		# do the subtract
	&st($a0,&QWPw(0,$rp));	# save
	 &cmpult($a2,$cc,$b2);	# will we borrow?
	&sub($a2,$cc,$a2);	# will we borrow?
	 &add($b2,$tmp,$cc);	# add the borrows

	&cmpult($a3,$b3,$t3);	# will we borrow?
	 &sub($a3,$b3,$a3);		# do the subtract
	&st($a1,&QWPw(1,$rp));	# save
	 &cmpult($a3,$cc,$b3);	# will we borrow?
	&sub($a3,$cc,$a3);	# will we borrow?
	 &add($b3,$t3,$cc);	# add the borrows

	&st($a2,&QWPw(2,$rp));	# save
	 &sub($count,4,$count);	# count-=4
	&st($a3,&QWPw(3,$rp));	# save
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

	&set_label("end");
	&function_end($name);
	}

