#!/usr/local/bin/perl -w

# Modified by Steve Henson. It should now read in the .err
# file and only add new error codes, retaining the old
# numbers. 

# Before it re-sorted new codes and re-ordered the whole thing. 
# This is the motivation for the change: the re numbering caused large
# patch files even if only one error or reason code was added.
# To force regeneration of all error codes (the old behaviour) use the
# -regen flag.

$regen = 0;

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
	elsif ($in =~ /^-regen/)
		{
		$regen = 1;
		next;
	}

	open(IN,"<$in") || die "unable to open '$in'\n";
	$last="";
	while (<IN>)
		{
		if (/err\(([A-Z0-9]+_F_[0-9A-Z_]+)\s*,\s*([0-9A-Z]+_R_[0-9A-Z_]+)\s*\)/)
			{
# Not sure what this was supposed to be for: it's broken anyway [steve]
#			if ($1 != $last)
#				{
#				if ($function{$1} == 0)
#					{
#					printf STDERR "$. $1 is bad\n";
#					}
#				}
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
	next if !defined $errfile{$j};
	next if $errfile{$j} eq "NONE";
	printf STDERR "doing %-6s - ",$j;
	@f=grep(/^${j}_/,@F);
	@r=grep(/^${j}_/,@R);
	if (defined($errfile{$j}))
		{
		read_errcodes($errfile{$j});
		# Check to see if any new codes: if not ignore.
		$new_codes = 0;
		foreach (@f) {
			if(!exists $func_codes{$_}) {
				$new_codes = 1;
				last;
			}
		}
		if(!$new_codes) {
			foreach (@r) {
				if(!exists $reason_codes{$_}) {
					$new_codes = 1;
					last;
				}
			}
		}
		if(!$new_codes) {
			print STDERR "No New Codes\n";
			next;
		}
		open(OUT,">$errfile{$j}") ||
			die "unable to open '$errfile{$j}':$!\n";
		$close_file=1;
		}
	else
		{
		$min_func = 100;
		$min_reason = 100;
		*OUT=*STDOUT;
		$close_file=0;
		}
	$num=$min_func;
	print OUT "/* Error codes for the $j functions. */\n\n";
	print OUT "/* Function codes. */\n";
	$f_count=0;
	foreach $i (@f)
		{
		$z=6-int(length($i)/8);
		if(exists $func_codes{$i}) {
			printf OUT "#define $i%s $func_codes{$i}\n","\t" x $z;
		} else {
			printf OUT "#define $i%s $num\n","\t" x $z;
			$num++;
		}
		$f_count++;
		}
	$num=$min_reason;
	print OUT "\n/* Reason codes. */\n";
	$r_count=0;
	foreach $i (@r)
		{
		$z=6-int(length($i)/8);
		if (exists $reason_codes{$i}) {
			printf OUT "#define $i%s $reason_codes{$i}\n","\t" x $z;
		} elsif (exists $r_value{$i}) {
			printf OUT "#define $i%s $r_value{$i}\n","\t" x $z;
		} else {
			printf OUT "#define $i%s $num\n","\t" x $z;
			$num++;
		}
		$r_count++;
		}
	close(OUT) if $close_file;

	printf STDERR "%3d functions, %3d reasons\n",$f_count,$r_count;
	}

# Read in the error codes and populate %function and %reason with the
# old codes. Also define $min_func and $min_reason with the smallest
# unused function and reason codes. Care is needed because the
# config file can define larger reason codes and these should be
# ignored.

sub read_errcodes {
$file = $_[0];
$min_func = 100;
$min_reason = 100;
undef %func_codes;
undef %reason_codes;
return if ($regen);
if (open IN, $file) {
	while(<IN>) {
		if(/^#define\s*(\S*)\s*(\S*)/) {
			if (exists $function{$1} ) {
				if($2 >= $min_func) {$min_func = $2 + 1;}
				$func_codes{$1} = $2;
			} elsif ((defined %reason) && exists $reason{$1}) {
				$reason_codes{$1} = $2;
				if( !(exists $r_value{$1})  &&
						 ($2 >= $min_reason))
							 {$min_reason = $2 + 1;}
			}
		}
	}
	close IN;
}
}
