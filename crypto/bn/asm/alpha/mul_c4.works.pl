#!/usr/local/bin/perl
# alpha assember 

sub mul_add_c
	{
	local($a,$b,$c0,$c1,$c2)=@_;
	local($l1,$h1,$t1,$t2);

print STDERR "count=$cnt\n"; $cnt++;
	&mul($a,$b,($l1)=&NR(1));
	&muh($a,$b,($h1)=&NR(1));
	&add($c0,$l1,$c0);
	&cmpult($c0,$l1,($t1)=&NR(1));	&FR($l1);
	&add($t1,$h1,$h1);		&FR($t1);
	&add($c1,$h1,$c1);
	&cmpult($c1,$h1,($t2)=&NR(1));	&FR($h1);
	&add($c2,$t2,$c2);		&FR($t2);
	}

sub bn_mul_comba4
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

	&ld(($a[0])=&NR(1),&QWPw(0,$ap));
	&ld(($b[0])=&NR(1),&QWPw(0,$bp));
	&ld(($a[1])=&NR(1),&QWPw(1,$ap));
	&ld(($b[1])=&NR(1),&QWPw(1,$bp));
	&ld(($a[2])=&NR(1),&QWPw(2,$ap));
	&ld(($b[2])=&NR(1),&QWPw(2,$bp));
	&ld(($a[3])=&NR(1),&QWPw(3,$ap));	&FR($ap);
	&ld(($b[3])=&NR(1),&QWPw(3,$bp));	&FR($bp);

	($c0,$c1,$c2)=&NR(3);
	&mov("zero",$c2);
	&mul($a[0],$b[0],$c0);
	&muh($a[0],$b[0],$c1);
	&st($c0,&QWPw(0,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[1],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(1,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[1],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[0],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[0],$c0,$c1,$c2);
	&st($c0,&QWPw(2,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[0],$b[3],$c0,$c1,$c2);	&FR($a[0]);
	&mul_add_c($a[1],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[2],$b[1],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[0],$c0,$c1,$c2);	&FR($b[0]);
	&st($c0,&QWPw(3,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[1],$b[3],$c0,$c1,$c2);	&FR($a[1]);
	&mul_add_c($a[2],$b[2],$c0,$c1,$c2);
	&mul_add_c($a[3],$b[1],$c0,$c1,$c2);	&FR($b[1]);
	&st($c0,&QWPw(4,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[2],$b[3],$c0,$c1,$c2);	&FR($a[2]);
	&mul_add_c($a[3],$b[2],$c0,$c1,$c2);	&FR($b[2]);
	&st($c0,&QWPw(5,$rp));			&FR($c0); ($c0)=&NR($c0);
	($c0,$c1,$c2)=($c1,$c2,$c0);
	&mov("zero",$c2);

	&mul_add_c($a[3],$b[3],$c0,$c1,$c2);	&FR($a[3],$b[3]);
	&st($c0,&QWPw(6,$rp));
	&st($c1,&QWPw(7,$rp));

	&FR($c0,$c1,$c2);

	&function_end($name);

	&fin_pool;
	}

1;
