#!/usr/local/bin/perl

while (@ARGV)
	{
	$in=shift(@ARGV);
	if ($in =~ /^-conf$/)
		{
		$in=shift(@ARGV);
		open(IN,"<$in") || die "unable to open '$in'\n";
		while (<IN>)
			{
			s/#.*$//;
			s/\s+$//;
			next if (/^$/);
			if (/^L\s+(\S+)\s+(\S+)$/)
				{ $errfile{$1}=$2; }
			elsif (/^F\s+(\S+)$/)
				{ $function{$1}=1; }
			elsif (/^R\s+(\S+)\s+(\S+)$/)
				{ $r_value{$1}=$2; }
			else { die "bad input line: $in:$.\n"; }
			}
		close(IN);
		next;
		}

	open(IN,"<$in") || die "unable to open '$in'\n";
	$last="";
	while (<IN>)
		{
		if (/err\(([A-Z0-9]+_F_[0-9A-Z_]+)\s*,\s*([0-9A-Z]+_R_[0-9A-Z_]+)\s*\)/)
			{
			if ($1 != $last)
				{
				if ($function{$1} == 0)
					{
					printf STDERR "$. $1 is bad\n";
					}
				}
			$function{$1}++;
			$last=$1;
			$reason{$2}++;
			}
		}
	close(IN);
	}

foreach (keys %function,keys %reason)
	{
	/^([A-Z0-9]+)_/;
	$prefix{$1}++;
	}

@F=sort keys %function;
@R=sort keys %reason;
foreach $j (sort keys %prefix)
	{
	next if $errfile{$j} eq "NONE";
	printf STDERR "doing %-6s - ",$j;
	if (defined($errfile{$j}))
		{
		open(OUT,">$errfile{$j}") ||
			die "unable to open '$errfile{$j}':$!\n";
		$close_file=1;
		}
	else
		{
		*OUT=*STDOUT;
		$close=0;
		}
	@f=grep(/^${j}_/,@F);
	@r=grep(/^${j}_/,@R);
	$num=100;
	print OUT "/* Error codes for the $j functions. */\n\n";
	print OUT "/* Function codes. */\n";
	$f_count=0;
	foreach $i (@f)
		{
		$z=6-int(length($i)/8);
		printf OUT "#define $i%s $num\n","\t" x $z;
		$num++;
		$f_count++;
		}
	$num=100;
	print OUT "\n/* Reason codes. */\n";
	$r_count=0;
	foreach $i (@r)
		{
		$z=6-int(length($i)/8);
		if (defined($r_value{$i}))
			{
			printf OUT "#define $i%s $r_value{$i}\n","\t" x $z;
			}
		else
			{
			printf OUT "#define $i%s $num\n","\t" x $z;
			$num++;
			}
		$r_count++;
		}
	close(OUT) if $close_file;

	printf STDERR "%3d functions, %3d reasons\n",$f_count,$r_count;
	}

