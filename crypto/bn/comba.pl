#!/usr/local/bin/perl

$num=8;
$num2=8/2;

print <<"EOF";
/* crypto/bn/bn_comba.c */
#include <stdio.h>
#include "bn_lcl.h"
/* Auto generated from crypto/bn/comba.pl
 */

#undef bn_mul_comba8
#undef bn_mul_comba4
#undef bn_sqr_comba8
#undef bn_sqr_comba4

#ifdef BN_LLONG
#define mul_add_c(a,b,c0,c1,c2) \\
	t=(BN_ULLONG)a*b; \\
	t1=(BN_ULONG)Lw(t); \\
	t2=(BN_ULONG)Hw(t); \\
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define mul_add_c2(a,b,c0,c1,c2) \\
	t=(BN_ULLONG)a*b; \\
	tt=(t+t)&BN_MASK; \\
	if (tt < t) c2++; \\
	t1=(BN_ULONG)Lw(tt); \\
	t2=(BN_ULONG)Hw(tt); \\
	c0=(c0+t1)&BN_MASK2;  \\
	if ((c0 < t1) && (((++t2)&BN_MASK2) == 0)) c2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c(a,i,c0,c1,c2) \\
	t=(BN_ULLONG)a[i]*a[i]; \\
	t1=(BN_ULONG)Lw(t); \\
	t2=(BN_ULONG)Hw(t); \\
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c2(a,i,j,c0,c1,c2) \\
	mul_add_c2((a)[i],(a)[j],c0,c1,c2)
#else
#define mul_add_c(a,b,c0,c1,c2) \\
	t1=LBITS(a); t2=HBITS(a); \\
	bl=LBITS(b); bh=HBITS(b); \\
	mul64(t1,t2,bl,bh); \\
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define mul_add_c2(a,b,c0,c1,c2) \\
	t1=LBITS(a); t2=HBITS(a); \\
	bl=LBITS(b); bh=HBITS(b); \\
	mul64(t1,t2,bl,bh); \\
	if (t2 & BN_TBIT) c2++; \\
	t2=(t2+t2)&BN_MASK2; \\
	if (t1 & BN_TBIT) t2++; \\
	t1=(t1+t1)&BN_MASK2; \\
	c0=(c0+t1)&BN_MASK2;  \\
	if ((c0 < t1) && (((++t2)&BN_MASK2) == 0)) c2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c(a,i,c0,c1,c2) \\
	sqr64(t1,t2,(a)[i]); \\
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \\
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define sqr_add_c2(a,i,j,c0,c1,c2) \\
	mul_add_c2((a)[i],(a)[j],c0,c1,c2)
#endif

void bn_mul_comba${num}(r,a,b)
BN_ULONG *r,*a,*b;
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

EOF
$ret=&combas_mul("r","a","b",$num,"c1","c2","c3");
printf <<"EOF";
	}

void bn_mul_comba${num2}(r,a,b)
BN_ULONG *r,*a,*b;
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

EOF
$ret=&combas_mul("r","a","b",$num2,"c1","c2","c3");
printf <<"EOF";
	}

void bn_sqr_comba${num}(r,a)
BN_ULONG *r,*a;
	{
#ifdef BN_LLONG
	BN_ULLONG t,tt;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

EOF
$ret=&combas_sqr("r","a",$num,"c1","c2","c3");
printf <<"EOF";
	}

void bn_sqr_comba${num2}(r,a)
BN_ULONG *r,*a;
	{
#ifdef BN_LLONG
	BN_ULLONG t,tt;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

EOF
$ret=&combas_sqr("r","a",$num2,"c1","c2","c3");
printf <<"EOF";
	}
EOF

sub bn_str
	{
	local($var,$val)=@_;
	print "\t$var=$val;\n";
	}

sub bn_ary
	{
	local($var,$idx)=@_;
	return("${var}[$idx]");
	}

sub bn_clr
	{
	local($var)=@_;

	print "\t$var=0;\n";
	}

sub bn_mad
	{
	local($a,$b,$c0,$c1,$c2,$num)=@_;

	if ($num == 2)
		{ printf("\tmul_add_c2($a,$b,$c0,$c1,$c2);\n"); }
	else
		{ printf("\tmul_add_c($a,$b,$c0,$c1,$c2);\n"); }
	}

sub bn_sad
	{
	local($a,$i,$j,$c0,$c1,$c2,$num)=@_;

	if ($num == 2)
		{ printf("\tsqr_add_c2($a,$i,$j,$c0,$c1,$c2);\n"); }
	else
		{ printf("\tsqr_add_c($a,$i,$c0,$c1,$c2);\n"); }
	}

sub combas_mul
	{
	local($r,$a,$b,$num,$c0,$c1,$c2)=@_;
	local($i,$as,$ae,$bs,$be,$ai,$bi);
	local($tot,$end);

	$as=0;
	$ae=0;
	$bs=0;
	$be=0;
	$tot=$num+$num-1;
	&bn_clr($c0);
	&bn_clr($c1);
	for ($i=0; $i<$tot; $i++)
		{
		$ai=$as;
		$bi=$bs;
		$end=$be+1;
		@numa=@numb=();

#print "($as $ae) ($bs $be) $bs -> $end [$i $num]\n";
		for ($j=$bs; $j<$end; $j++)
			{
			push(@numa,$ai);
			push(@numb,$bi);
			$ai--;
			$bi++;
			}

		if ($i & 1)
			{
			@numa=reverse(@numa);
			@numb=reverse(@numb);
			}

		&bn_clr($c2);
		for ($j=0; $j<=$#numa; $j++)
			{
			&bn_mad(&bn_ary($a,$numa[$j]),
				&bn_ary($b,$numb[$j]),$c0,$c1,$c2,1);
			}
		&bn_str(&bn_ary($r,$i),$c0);
		($c0,$c1,$c2)=($c1,$c2,$c0);

		$as++ if ($i < ($num-1));
		$ae++ if ($i >= ($num-1));

		$bs++ if ($i >= ($num-1));
		$be++ if ($i < ($num-1));
		}
	&bn_str(&bn_ary($r,$i),$c0);
	}

sub combas_sqr
	{
	local($r,$a,$num,$c0,$c1,$c2)=@_;
	local($i,$as,$ae,$bs,$be,$ai,$bi);
	local($b,$tot,$end,$half);

	$b=$a;
	$as=0;
	$ae=0;
	$bs=0;
	$be=0;
	$tot=$num+$num-1;
	&bn_clr($c0);
	&bn_clr($c1);
	for ($i=0; $i<$tot; $i++)
		{
		$ai=$as;
		$bi=$bs;
		$end=$be+1;
		@numa=@numb=();

#print "($as $ae) ($bs $be) $bs -> $end [$i $num]\n";
		for ($j=$bs; $j<$end; $j++)
			{
			push(@numa,$ai);
			push(@numb,$bi);
			$ai--;
			$bi++;
			last if ($ai < $bi);
			}
		if (!($i & 1))
			{
			@numa=reverse(@numa);
			@numb=reverse(@numb);
			}

		&bn_clr($c2);
		for ($j=0; $j <= $#numa; $j++)
			{
			if ($numa[$j] == $numb[$j])
				{&bn_sad($a,$numa[$j],$numb[$j],$c0,$c1,$c2,1);}
			else
				{&bn_sad($a,$numa[$j],$numb[$j],$c0,$c1,$c2,2);}
			}
		&bn_str(&bn_ary($r,$i),$c0);
		($c0,$c1,$c2)=($c1,$c2,$c0);

		$as++ if ($i < ($num-1));
		$ae++ if ($i >= ($num-1));

		$bs++ if ($i >= ($num-1));
		$be++ if ($i < ($num-1));
		}
	&bn_str(&bn_ary($r,$i),$c0);
	}
