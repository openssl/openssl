#!/usr/local/bin/perl

sub lab_shift
	{
	local(*a,$n)=@_;
	local(@r,$i,$j,$k,$d,@z);

	@r=&shift(*a,$n);
	foreach $i (0 .. 31)
		{
		@z=split(/\^/,$r[$i]);
		for ($j=0; $j <= $#z; $j++)
			{
			($d)=($z[$j] =~ /^(..)/);
			($k)=($z[$j] =~ /\[(.*)\]$/);
			$k.=",$n" if ($k ne "");
			$k="$n"	  if ($k eq "");
			$d="$d[$k]";
			$z[$j]=$d;
			}
		$r[$i]=join('^',@z);
		}
	return(@r);
	}

sub shift
	{
	local(*a,$n)=@_;
	local(@f);

	if ($n > 0)
		{
		@f=&shiftl(*a,$n);
		}
	else
		{
		@f=&shiftr(*a,-$n);
		}
	return(@f);
	}

sub rotate
	{
	local(*a,$n)=@_;
	local(@f);

	if ($n > 0)
		{ @f=&rotatel(*a,$n); }
	else
		{ @f=&rotater(*a,-$n); }
	return(@f);
	}

sub rotater
	{
	local(*a,$n)=@_;
	local(@f,@g);

	@f=&shiftr(*a,$n);
	@g=&shiftl(*a,32-$n);
	$#f=31;
	$#g=31;
	return(&or(*f,*g));
	}

sub rotatel
	{
	local(*a,$n)=@_;
	local(@f,@g);

	@f=&shiftl(*a,$n);
	@g=&shiftr(*a,32-$n);
	$#f=31;
	$#g=31;
	return(&or(*f,*g));
	}

sub shiftr
	{
	local(*a,$n)=@_;
	local(@r,$i);

	$#r=31;
	foreach $i (0 .. 31)
		{
		if (($i+$n) > 31)
			{
			$r[$i]="--";
			}
		else
			{
			$r[$i]=$a[$i+$n];
			}
		}
	return(@r);
	}

sub shiftl
	{
	local(*a,$n)=@_;
	local(@r,$i);

	$#r=31;
	foreach $i (0 .. 31)
		{
		if ($i < $n)
			{
			$r[$i]="--";
			}
		else
			{
			$r[$i]=$a[$i-$n];
			}
		}
	return(@r);
	}

sub printit
	{
	local(@a)=@_;
	local($i);

	foreach $i (0 .. 31)
		{
		printf "%2s  ",$a[$i];
		print "\n" if (($i%8) == 7);
		}
	print "\n";
	}

sub xor
	{
	local(*a,*b)=@_;
	local(@r,$i);

	$#r=31;
	foreach $i (0 .. 31)
		{
		$r[$i]=&compress($a[$i].'^'.$b[$i]);
#		$r[$i]=$a[$i]."^".$b[$i];
		}
	return(@r);
	}

sub and
	{
	local(*a,$m)=@_;
	local(@r,$i);

	$#r=31;
	foreach $i (0 .. 31)
		{
		$r[$i]=(($m & (1<<$i))?($a[$i]):('--'));
		}
	return(@r);
	}

sub or
	{
	local(*a,*b)=@_;
	local(@r,$i);

	$#r=31;
	foreach $i (0 .. 31)
		{
		$r[$i]='--'   if (($a[$i] eq '--') && ($b[$i] eq '--'));
		$r[$i]=$a[$i] if (($a[$i] ne '--') && ($b[$i] eq '--'));
		$r[$i]=$b[$i] if (($a[$i] eq '--') && ($b[$i] ne '--'));
		$r[$i]='++'   if (($a[$i] ne '--') && ($b[$i] ne '--'));
		}
	return(@r);
	}

sub compress
	{
	local($s)=@_;
	local($_,$i,@a,%a,$r);

	$s =~ s/\^\^/\^/g;
	$s =~ s/^\^//;
	$s =~ s/\^$//;
	@a=split(/\^/,$s);

	while ($#a >= 0)
		{
		$_=shift(@a);
		next unless /\d/;
		$a{$_}++;
		}
	foreach $i (sort keys %a)
		{
		next if ($a{$i}%2 == 0);
		$r.="$i^";
		}
	chop($r);
	return($r);
	}
1;
