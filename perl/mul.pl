#!/usr/bin/perl

use ExtUtils::testlib;

use SSLeay;


sub mul
	{
	my($ab,$cd,$num)=@_;

	if ($num <= 4096)
		{
		return($ab*$cd);
		}
	else
		{
		my($a,$b,$c,$d,$n,$ac,$bd,$m,$t1,$t2);

		$n=$num/2;

		$a=$ab->mask_bits($n);
		$b=$ab->rshift($n);
		$c=$cd->mask_bits($n);
		$d=$cd->rshift($n);

		$t1=($b-$a);
		$t2=($c-$d);
		$m= &mul($t1,$t2,$n);
		$ac=&mul($a,$c,$n);
		$bd=&mul($b,$d,$n);
		$m=$m+$ac+$bd;
		$m=$m->lshift($n);
		$bd=$bd->lshift($num);

		$r=$ac+$m+$bd;
		return($r);
		}
	}

$num=4096*32;
$a=SSLeay::BN::rand($num);
$b=SSLeay::BN::rand($num);

#for (1 .. 10)
	{
	$r=&mul($a,$b,$num);
	}

#for (1 .. 10)
	{
	$rr=$a*$b;
	}

$res=$rr-$r;
print $res->bn2hex()."\n";
