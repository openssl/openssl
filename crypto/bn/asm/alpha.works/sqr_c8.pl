#!/usr/local/bin/perl
# alpha assember 

sub bn_sqr_comba8
	{
	local($name)=@_;
	local(@a,@b,$r,$c0,$c1,$c2);

	$cnt=1;
	&init_pool(2);

	$rp=&wparam(0);
	$ap=&wparam(1);

	&function_begin($name,"");

	&comment("");

	&ld(($a[0])=&NR(1),&QWPw(0,$ap));
	&ld(($a[1])=&NR(1),&QWPw(1,$ap));
	&ld(($a[2])=&NR(1),&QWPw(2,$ap));
	&ld(($a[3])=&NR(1),&QWPw(3,$ap));
	&ld(($a[4])=&NR(1),&QWPw(4,$ap));
	&ld(($a[5])=&NR(1),&QWPw(5,$ap));
	&ld(($a[6])=&NR(1),&QWPw(6,$ap));
        &ld(($a[7])=&NR(1),&QWPw(7,$ap)); &FR($ap);

	($c0,$c1,$c2)=&NR(3);

	&mov("zero",$c2);
	&mul($a[0],$a[0],$c0);
	&muh($a[0],$a[0],$c1);
	&st($c0,&QWPw(0,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[1],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(1,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[2],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(2,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[2],$a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[3],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(3,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[3],$a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[4],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(4,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[3],$a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[4],$a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[5],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(5,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[3],$c0,$c1,$c2);
	&sqr_add_c2($a[4],$a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[5],$a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[6],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(6,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[4],$a[3],$c0,$c1,$c2);
	&sqr_add_c2($a[5],$a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[6],$a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(7,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[4],$c0,$c1,$c2);
	&sqr_add_c2($a[5],$a[3],$c0,$c1,$c2);
	&sqr_add_c2($a[6],$a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[1],$c0,$c1,$c2);
	&st($c0,&QWPw(8,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[5],$a[4],$c0,$c1,$c2);
	&sqr_add_c2($a[6],$a[3],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[2],$c0,$c1,$c2);
	&st($c0,&QWPw(9,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[5],$c0,$c1,$c2);
	&sqr_add_c2($a[6],$a[4],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[3],$c0,$c1,$c2);
	&st($c0,&QWPw(10,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[6],$a[5],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[4],$c0,$c1,$c2);
	&st($c0,&QWPw(11,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[6],$c0,$c1,$c2);
	&sqr_add_c2($a[7],$a[5],$c0,$c1,$c2);
	&st($c0,&QWPw(12,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[7],$a[6],$c0,$c1,$c2);
	&st($c0,&QWPw(13,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[7],$c0,$c1,$c2);
	&st($c0,&QWPw(14,$rp));
	&st($c1,&QWPw(15,$rp));

	&function_end($name);

	&fin_pool;
	}

1;
