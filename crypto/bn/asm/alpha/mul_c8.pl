#!/usr/local/bin/perl
# alpha assember 

sub bn_mul_comba8
	{
	local($name)=@_;
	local(@a,@b,$r,$c0,$c1,$c2);

	$cnt=1;
	&init_pool(3);

	$rp=&wparam(0);
	$ap=&wparam(1);
	$bp=&wparam(2);

	&function_begin($name,"");

	&comment("");

	&stack_push(2);
	&ld(($a[0])=&NR(1),&QWPw(0,$ap));
	&ld(($b[0])=&NR(1),&QWPw(0,$bp));
	&st($reg_s0,&swtmp(0)); &FR($reg_s0);
	&st($reg_s1,&swtmp(1)); &FR($reg_s1);
	&ld(($a[1])=&NR(1),&QWPw(1,$ap));
	&ld(($b[1])=&NR(1),&QWPw(1,$bp));
	&ld(($a[2])=&NR(1),&QWPw(2,$ap));
	&ld(($b[2])=&NR(1),&QWPw(2,$bp));
	&ld(($a[3])=&NR(1),&QWPw(3,$ap));
	&ld(($b[3])=&NR(1),&QWPw(3,$bp));
	&ld(($a[4])=&NR(1),&QWPw(1,$ap));
	&ld(($b[4])=&NR(1),&QWPw(1,$bp));
	&ld(($a[5])=&NR(1),&QWPw(1,$ap));
	&ld(($b[5])=&NR(1),&QWPw(1,$bp));
	&ld(($a[6])=&NR(1),&QWPw(1,$ap));
	&ld(($b[6])=&NR(1),&QWPw(1,$bp));
	&ld(($a[7])=&NR(1),&QWPw(1,$ap));	&FR($ap);
	&ld(($b[7])=&NR(1),&QWPw(1,$bp));	&FR($bp);

	($c0,$c1,$c2)=&NR(3);
	&mov("zero",$c2);
	&mul($a[0],$b[0],$c0);
	&muh($a[0],$b[0],$c1);
	&st($c0,&QWPw(0,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(1,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(2,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(3,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(4,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(5,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(6,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[7],$c0,$c1,$c2);	&FR($a[0]);
	&mul_add_c($a[1],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[0],$c0,$c1,$c2);	&FR($b[0]);
	&st($c0,&QWPw(7,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[1],$b[7],$c0,$c1,$c2);	&FR($a[1]);
	&mul_add_c($a[2],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[1],$c0,$c1,$c2);	&FR($b[1]);
	&st($c0,&QWPw(8,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[2],$b[7],$c0,$c1,$c2);	&FR($a[2]);
	&mul_add_c($a[3],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[4],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[3],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[2],$c0,$c1,$c2);	&FR($b[2]);
	&st($c0,&QWPw(9,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[3],$b[7],$c0,$c1,$c2);	&FR($a[3]);
	&mul_add_c($a[4],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[5],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[4],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[3],$c0,$c1,$c2);	&FR($b[3]);
	&st($c0,&QWPw(10,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[4],$b[7],$c0,$c1,$c2);	&FR($a[4]);
	&mul_add_c($a[5],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[6],$b[5],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[4],$c0,$c1,$c2);	&FR($b[4]);
	&st($c0,&QWPw(11,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[5],$b[7],$c0,$c1,$c2);	&FR($a[5]);
	&mul_add_c($a[6],$b[6],$c0,$c1,$c2);
	&mul_add_c($a[7],$b[5],$c0,$c1,$c2);	&FR($b[5]);
	&st($c0,&QWPw(12,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[6],$b[7],$c0,$c1,$c2);	&FR($a[6]);
	&mul_add_c($a[7],$b[6],$c0,$c1,$c2);	&FR($b[6]);
	&st($c0,&QWPw(13,$rp));			&FR($c0); ($c0)=&NR(1);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[7],$b[7],$c0,$c1,$c2);	&FR($a[7],$b[7]);
	&st($c0,&QWPw(14,$rp));
	&st($c1,&QWPw(15,$rp));

	&FR($c0,$c1,$c2);

	&ld($reg_s0,&swtmp(0));
	&ld($reg_s1,&swtmp(1));
	&stack_pop(2);

	&function_end($name);

	&fin_pool;
	}

1;
