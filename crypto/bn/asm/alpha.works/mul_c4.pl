#!/usr/local/bin/perl
# alpha assember 

sub mul_add_c
	{
	local($a,$b,$c0,$c1,$c2)=@_;
	local($l1,$h1,$t1,$t2);

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
	&mul($a[0],$b[0],($r00)=&NR(1));
	&ld(($a[2])=&NR(1),&QWPw(2,$ap));
	&ld(($b[2])=&NR(1),&QWPw(2,$bp));
	&muh($a[0],$b[0],($r01)=&NR(1));
	&FR($ap); &ld(($a[3])=&NR(1),&QWPw(3,$ap));
	&FR($bp); &ld(($b[3])=&NR(1),&QWPw(3,$bp));
	&mul($a[0],$b[1],($r02)=&NR(1));

	($R,$H1,$H2)=&NR(3);

	&st($r00,&QWPw(0,$rp));	&FR($r00);

	&mov("zero",$R);
	&mul($a[1],$b[0],($r03)=&NR(1));

	&mov("zero",$H1);
	&mov("zero",$H0);
	 &add($R,$r01,$R);
	&muh($a[0],$b[1],($r04)=&NR(1));
	 &cmpult($R,$r01,($t01)=&NR(1));	&FR($r01);
	 &add($R,$r02,$R);
	 &add($H1,$t01,$H1)			&FR($t01);
	&muh($a[1],$b[0],($r05)=&NR(1));
	 &cmpult($R,$r02,($t02)=&NR(1));	&FR($r02);
	 &add($R,$r03,$R);
	 &add($H2,$t02,$H2)			&FR($t02);
	&mul($a[0],$b[2],($r06)=&NR(1));
	 &cmpult($R,$r03,($t03)=&NR(1));	&FR($r03);
	 &add($H1,$t03,$H1)			&FR($t03);
	&st($R,&QWPw(1,$rp));
	&add($H1,$H2,$R);

	&mov("zero",$H1);
	 &add($R,$r04,$R);
	&mov("zero",$H2);
	&mul($a[1],$b[1],($r07)=&NR(1));
	 &cmpult($R,$r04,($t04)=&NR(1));	&FR($r04);
	 &add($R,$r05,$R);
	 &add($H1,$t04,$H1)			&FR($t04);
	&mul($a[2],$b[0],($r08)=&NR(1));
	 &cmpult($R,$r05,($t05)=&NR(1));	&FR($r05);
	 &add($R,$r01,$R);
	 &add($H2,$t05,$H2)			&FR($t05);
	&muh($a[0],$b[2],($r09)=&NR(1));
	 &cmpult($R,$r06,($t06)=&NR(1));	&FR($r06);
	 &add($R,$r07,$R);
	 &add($H1,$t06,$H1)			&FR($t06);
	&muh($a[1],$b[1],($r10)=&NR(1));
	 &cmpult($R,$r07,($t07)=&NR(1));	&FR($r07);
	 &add($R,$r08,$R);
	 &add($H2,$t07,$H2)			&FR($t07);
	&muh($a[2],$b[0],($r11)=&NR(1));
	 &cmpult($R,$r08,($t08)=&NR(1));	&FR($r08);
	 &add($H1,$t08,$H1)			&FR($t08);
	&st($R,&QWPw(2,$rp));
	&add($H1,$H2,$R);

	&mov("zero",$H1);
	 &add($R,$r09,$R);
	&mov("zero",$H2);
	&mul($a[0],$b[3],($r12)=&NR(1));
	 &cmpult($R,$r09,($t09)=&NR(1));	&FR($r09);
	 &add($R,$r10,$R);
	 &add($H1,$t09,$H1)			&FR($t09);
	&mul($a[1],$b[2],($r13)=&NR(1));
	 &cmpult($R,$r10,($t10)=&NR(1));	&FR($r10);
	 &add($R,$r11,$R);
	 &add($H1,$t10,$H1)			&FR($t10);
	&mul($a[2],$b[1],($r14)=&NR(1));
	 &cmpult($R,$r11,($t11)=&NR(1));	&FR($r11);
	 &add($R,$r12,$R);
	 &add($H1,$t11,$H1)			&FR($t11);
	&mul($a[3],$b[0],($r15)=&NR(1));
	 &cmpult($R,$r12,($t12)=&NR(1));	&FR($r12);
	 &add($R,$r13,$R);
	 &add($H1,$t12,$H1)			&FR($t12);
	&muh($a[0],$b[3],($r16)=&NR(1));
	 &cmpult($R,$r13,($t13)=&NR(1));	&FR($r13);
	 &add($R,$r14,$R);
	 &add($H1,$t13,$H1)			&FR($t13);
	&muh($a[1],$b[2],($r17)=&NR(1));
	 &cmpult($R,$r14,($t14)=&NR(1));	&FR($r14);
	 &add($R,$r15,$R);
	 &add($H1,$t14,$H1)			&FR($t14);
	&muh($a[2],$b[1],($r18)=&NR(1));
	 &cmpult($R,$r15,($t15)=&NR(1));	&FR($r15);
	 &add($H1,$t15,$H1)			&FR($t15);
	&st($R,&QWPw(3,$rp));
	&add($H1,$H2,$R);

	&mov("zero",$H1);
	 &add($R,$r16,$R);
	&mov("zero",$H2);
	&muh($a[3],$b[0],($r19)=&NR(1));
	 &cmpult($R,$r16,($t16)=&NR(1));	&FR($r16);
	 &add($R,$r17,$R);
	 &add($H1,$t16,$H1)			&FR($t16);
	&mul($a[1],$b[3],($r20)=&NR(1));
	 &cmpult($R,$r17,($t17)=&NR(1));	&FR($r17);
	 &add($R,$r18,$R);
	 &add($H1,$t17,$H1)			&FR($t17);
	&mul($a[2],$b[2],($r21)=&NR(1));
	 &cmpult($R,$r18,($t18)=&NR(1));	&FR($r18);
	 &add($R,$r19,$R);
	 &add($H1,$t18,$H1)			&FR($t18);
	&mul($a[3],$b[1],($r22)=&NR(1));
	 &cmpult($R,$r19,($t19)=&NR(1));	&FR($r19);
	 &add($R,$r20,$R);
	 &add($H1,$t19,$H1)			&FR($t19);
	&muh($a[1],$b[3],($r23)=&NR(1));
	 &cmpult($R,$r20,($t20)=&NR(1));	&FR($r20);
	 &add($R,$r21,$R);
	 &add($H1,$t20,$H1)			&FR($t20);
	&muh($a[2],$b[2],($r24)=&NR(1));
	 &cmpult($R,$r21,($t21)=&NR(1));	&FR($r21);
	 &add($R,$r22,$R);
	 &add($H1,$t21,$H1)			&FR($t21);
	&muh($a[3],$b[1],($r25)=&NR(1));
	 &cmpult($R,$r22,($t22)=&NR(1));	&FR($r22);
	 &add($H1,$t22,$H1)			&FR($t22);
	&st($R,&QWPw(4,$rp));
	&add($H1,$H2,$R);

	&mov("zero",$H1);
	 &add($R,$r23,$R);
	&mov("zero",$H2);
	&mul($a[2],$b[3],($r26)=&NR(1));
	 &cmpult($R,$r23,($t23)=&NR(1));	&FR($r23);
	 &add($R,$r24,$R);
	 &add($H1,$t23,$H1)			&FR($t23);
	&mul($a[3],$b[2],($r27)=&NR(1));
	 &cmpult($R,$r24,($t24)=&NR(1));	&FR($r24);
	 &add($R,$r25,$R);
	 &add($H1,$t24,$H1)			&FR($t24);
	&muh($a[2],$b[3],($r28)=&NR(1));
	 &cmpult($R,$r25,($t25)=&NR(1));	&FR($r25);
	 &add($R,$r26,$R);
	 &add($H1,$t25,$H1)			&FR($t25);
	&muh($a[3],$b[2],($r29)=&NR(1));
	 &cmpult($R,$r26,($t26)=&NR(1));	&FR($r26);
	 &add($R,$r27,$R);
	 &add($H1,$t26,$H1)			&FR($t26);
	&mul($a[3],$b[3],($r30)=&NR(1));
	 &cmpult($R,$r27,($t27)=&NR(1));	&FR($r27);
	 &add($H1,$t27,$H1)			&FR($t27);
	&st($R,&QWPw(5,$rp));
	&add($H1,$H2,$R);

	&mov("zero",$H1);
	 &add($R,$r28,$R);
	&mov("zero",$H2);
	&muh($a[3],$b[3],($r31)=&NR(1));
	 &cmpult($R,$r28,($t28)=&NR(1));	&FR($r28);
	 &add($R,$r29,$R);
	 &add($H1,$t28,$H1)			&FR($t28);
	############
	 &cmpult($R,$r29,($t29)=&NR(1));	&FR($r29);
	 &add($R,$r30,$R);
	 &add($H1,$t29,$H1)			&FR($t29);
        ############
	 &cmpult($R,$r30,($t30)=&NR(1));	&FR($r30);
	 &add($H1,$t30,$H1)			&FR($t30);
	&st($R,&QWPw(6,$rp));
	&add($H1,$H2,$R);

	 &add($R,$r31,$R);			&FR($r31);
	&st($R,&QWPw(7,$rp));

	&FR($R,$H1,$H2);
	&function_end($name);

	&fin_pool;
	}

1;
