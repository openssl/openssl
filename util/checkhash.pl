#!/usr/local/bin/perl -w

my $change_dir = "";
my $check_program = "sha1/fips_standalone_sha1";

my $verbose = 0;
my $badfiles = 0;
my $rebuild = 0;
my $force_rewrite = 0;
my $hash_file = "fipshashes.sha1";
my $recurse = 0;

my @fingerprint_files;

while (@ARGV)
	{
	my $arg = $ARGV[0];
	if ($arg eq "-chdir")
		{
		shift @ARGV;
		$change_dir = shift @ARGV;
		}
	elsif ($arg eq "-rebuild")
		{
		shift @ARGV;
		$rebuild = 1;
		}
	elsif ($arg eq "-verbose")
		{
		shift @ARGV;
		$verbose = 1;
		}
	elsif ($arg eq "-force-rewrite")
		{
		shift @ARGV;
		$force_rewrite = 1;
		}
	elsif ($arg eq "-hash_file")
		{
		shift @ARGV;
		$hash_file = shift @ARGV;
		}
	elsif ($arg eq "-recurse")
		{
		shift @ARGV;
		$recurse = 1;
		}
	elsif ($arg eq "-program_path")
		{
		shift @ARGV;
		$check_program = shift @ARGV;
		}
	else
		{
		die "Unknown Option $arg";
		}

	}

chdir $change_dir if $change_dir ne "";

if ($recurse)
	{
	@fingerprint_files = ("fingerprint.sha1",
				<*/fingerprint.sha1>);
	}
else
	{
	push @fingerprint_files, $hash_file;
	}

foreach $fp (@fingerprint_files)
	{
	open(IN, "$fp") || die "Can't open file $fp";
	print STDERR "Opening Fingerprint file $fp\n" if $verbose;
	my $dir = $fp;
	$dir =~ s/[^\/]*$//;
	while (<IN>)
		{
		chomp;
		if (!(($file, $hash) = /^HMAC-SHA1\((.*)\)\s*=\s*(\w*)$/))
			{
			print STDERR "FATAL: Invalid syntax in file $fp\n";
			print STDERR "Line:\n$_\n";
			fatal_error();
			}
		if (!$rebuild && length($hash) != 40)
			{
			print STDERR "FATAL: Invalid hash length in $fp for file $file\n";
			fatal_error();
			}
		push @hashed_files, "$dir$file";
		if (exists $hashes{"$dir$file"})
			{
			print STDERR "FATAL: Duplicate Hash file $dir$file\n";
			fatal_error();
			}
		if (! -r "$dir$file")
			{
			print STDERR "FATAL: Can't access $dir$file\n";
			fatal_error();
			}
		$hashes{"$dir$file"} = $hash;
		}
	close IN;
	}

@checked_hashes = `$check_program @hashed_files`;

if ($? != 0)
	{
	print STDERR "Error running hash program $check_program\n";
	fatal_error();
	}

if (@checked_hashes != @hashed_files)
	{
	print STDERR "FATAL: hash count incorrect\n";
	fatal_error();
	}

foreach (@checked_hashes)
	{
	chomp;
	if (!(($file, $hash) = /^HMAC-SHA1\((.*)\)\s*=\s*(\w*)$/))
		{
		print STDERR "FATAL: Invalid syntax in file $fp\n";
		print STDERR "Line:\n$_\n";
		fatal_error();
		}
	if (length($hash) != 40)
		{
		print STDERR "FATAL: Invalid hash length for file $file\n";
		fatal_error();
		}
	if ($hash ne $hashes{$file})
		{
		if ($rebuild)
			{
			print STDERR "Updating hash on file $file\n";
			$hashes{$file} = $hash;
			}
		else
			{
			print STDERR "Hash check failed for file $file\n";
			}
		$badfiles++;
		}
	elsif ($verbose)
		{ print "Hash Check OK for $file\n";}
	}
	

if ($badfiles && !$rebuild)
	{
	print STDERR "FATAL: hash mismatch on $badfiles files\n";
	fatal_error();
	}

if ($badfiles || $force_rewrite)
	{
	print "Updating Hash file $hash_file\n";
	open OUT, ">$hash_file" || die "Error rewriting $hash_file";
	foreach (@hashed_files)
		{
		print OUT "HMAC-SHA1($_)= $hashes{$_}\n";
		}
	close OUT;
	}

if (!$badfiles)
	{
	print "FIPS hash check successful\n";
	}


sub fatal_error
	{
	print STDERR "*** Your source code does not match the FIPS validated source ***\n";
	exit 1;
	}
