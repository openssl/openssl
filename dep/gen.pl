#!/usr/local/bin/perl

require 'getopts.pl';

$files="files";
%have=();
%missing=();
%name=();
%func=();

&Getopts('Ff:');

&load_file("files");
foreach $file (@ARGV)
	{ &do_nm($file); }

if (defined($opt_f))
	{
	%a=();
	$r=&list_files($opt_f,"",*a);
	if ($opt_F)
		{
		foreach (sort split(/\n/,$r))
			{ print "$_\n"; }
		}
	else
		{ print $r; }
	}
else
	{
	for (sort keys %have)
		{
		print "$_:$have{$_}\n";
		}
	}

sub list_files
	{
	local($f,$o,*done)=@_;
	local($a,$_,$ff,$ret);

	return if $f =~ /^\s*$/;

	$done{$f}=1;
	$ret.=$f."\n" if $opt_F;
	foreach (split(/ /,$have{$f}))
		{
		$ret.="$o$f:$_\n" unless $opt_F;
		}

	foreach (split(/ /,$missing{$f}))
		{
		$ff=$func{$_};
		next if defined($done{$ff});
		$ret.=&list_files($ff,$o."	");
		}
	$ret;
	}

sub do_nm
	{
	local($file)=@_;
	local($fname)="";

	open(IN,"nm $file|") || die "unable to run 'nm $file|':$!\n";
	while (<IN>)
		{
		chop;
		next if /^\s*$/;
		if (/^(.*)\.o:\s*$/)
			{
			$fname="$1.c";
			next;
			}
		($type,$name)=/^.{8} (.) (.+)/;
#		print "$fname $type $name\n";

		if ($type eq "T")
			{
			$have{$fname}.="$name ";
			$func{$name}=$fname;
			}
		elsif ($type eq "U")
			{
			$missing{$fname}.="$name ";
			}
		}
	close(IN);
	}

sub load_file
	{
	local($file)=@_;

	open(IN,"<$files") || die "unable to open $files:$!\n";

	while (<IN>)
		{
		chop;
		next if /^\s*$/;
		($n)=/\/([^\/\s]+)\s+/;
		($fn)=/^(\S+)\s/;
#		print "$n - $fn\n";
		if (defined($name{$n}))
			{ print "$n already exists\n"; }
		else
			{ $name{$n}=$fn; }
		}
	close(IN);
	@name=%name;
	}


