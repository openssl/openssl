#!/usr/local/bin/perl
# alpha assember 

sub sqr_add_c
	{
	local($a,$c0,$c1,$c2)=@_;
	local($l1,$h1,$t1,$t2);

	&mul($a,$a,($l1)=&NR(1));
	&muh($a,$a,($h1)=&NR(1));
	&add($c0,$l1,$c0);
	&add($c1,$h1,$c1);
	&cmpult($c0,$l1,($t1)=&NR(1));	&FR($l1);
	&cmpult($c1,$h1,($t2)=&NR(1));	&FR($h1);
	&add($c1,$t1,$c1);		&FR($t1);
	&add($c2,$t2,$c2);		&FR($t2);
	}

sub sqr_add_c2
	{
	local($a,$b,$c0,$c1,$c2)=@_;
	local($l1,$h1,$t1,$t2);

	&mul($a,$b,($l1)=&NR(1));
	&muh($a,$b,($h1)=&NR(1));
	&cmplt($l1,"zero",($lc1)=&NR(1));
	&cmplt($h1,"zero",($hc1)=&NR(1));
	&add($l1,$l1,$l1);
	&add($h1,$h1,$h1);
	&add($h1,$lc1,$h1);		&FR($lc1);
	&add($c2,$hc1,$c2);		&FR($hc1);

	&add($c0,$l1,$c0);
	&add($c1,$h1,$c1);
	&cmpult($c0,$l1,($lc1)=&NR(1));	&FR($l1);
	&cmpult($c1,$h1,($hc1)=&NR(1));	&FR($h1);

	&add($c1,$lc1,$c1);		&FR($lc1);
	&add($c2,$hc1,$c2);		&FR($hc1);
	}


sub bn_sqr_comba4
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
        &ld(($a[3])=&NR(1),&QWPw(3,$ap)); &FR($ap);

	($c0,$c1,$c2)=&NR(3);

	&mov("zero",$c2);
	&mul($a[0],$a[0],$c0);
	&muh($a[0],$a[0],$c1);
	&st($c0,&QWPw(0,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[0],$a[1],$c0,$c1,$c2);
	&st($c0,&QWPw(1,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[1],$c0,$c1,$c2);
	&sqr_add_c2($a[2],$a[0],$c0,$c1,$c2);
	&st($c0,&QWPw(2,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[3],$a[0],$c0,$c1,$c2);
	&sqr_add_c2($a[2],$a[1],$c0,$c1,$c2);
	&st($c0,&QWPw(3,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[2],$c0,$c1,$c2);
	&sqr_add_c2($a[3],$a[1],$c0,$c1,$c2);
	&st($c0,&QWPw(4,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c2($a[3],$a[2],$c0,$c1,$c2);
	&st($c0,&QWPw(5,$rp));
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&sqr_add_c($a[3],$c0,$c1,$c2);
	&st($c0,&QWPw(6,$rp));
	&st($c1,&QWPw(7,$rp));

	&function_end($name);

	&fin_pool;
	}

1;
