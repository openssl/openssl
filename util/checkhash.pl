#!/usr/bin/env perl -w

my $package = caller;

if (!(defined $package))
	{
	my $retval = check_hashes(@ARGV);
	exit $retval;
	}

1;

sub check_hashes
	{

	my @args = @_;

	my $change_dir = "";
	my $check_program = "sha/fips_standalone_sha1";

	my $verbose = 0;
	my $badfiles = 0;
	my $rebuild = 0;
	my $force_rewrite = 0;
	my $hash_file = "fipshashes.c";
	my $recurse = 0;

	my @fingerprint_files;

	while (@args)
		{
		my $arg = $args[0];
		if ($arg eq "-chdir")
			{
			shift @args;
			$change_dir = shift @args;
			}
		elsif ($arg eq "-rebuild")
			{
			shift @args;
			$rebuild = 1;
			}
		elsif ($arg eq "-verbose")
			{
			shift @args;
			$verbose = 1;
			}
		elsif ($arg eq "-force-rewrite")
			{
			shift @args;
			$force_rewrite = 1;
			}
		elsif ($arg eq "-hash_file")
			{
			shift @args;
			$hash_file = shift @args;
			}
		elsif ($arg eq "-recurse")
			{
			shift @args;
			$recurse = 1;
			}
		elsif ($arg eq "-program_path")
			{
			shift @args;
			$check_program = shift @args;
			}
		else
			{
			print STDERR "Unknown Option $arg";
			return 1;
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
		if (!open(IN, "$fp"))
			{
			print STDERR "Can't open file $fp";
			return 1;
			}
		print STDERR "Opening Fingerprint file $fp\n" if $verbose;
		my $dir = $fp;
		$dir =~ s/[^\/]*$//;
		while (<IN>)
			{
			chomp;
			if (!(($file, $hash) = /^\"HMAC-SHA1\((.*)\)\s*=\s*(\w*)\",$/))
				{
				/^\"/ || next;
				print STDERR "FATAL: Invalid syntax in file $fp\n";
				print STDERR "Line:\n$_\n";
				fatal_error();
				return 1;
				}
			if (!$rebuild && length($hash) != 40)
				{
				print STDERR "FATAL: Invalid hash length in $fp for file $file\n";
				fatal_error();
				return 1;
				}
			push @hashed_files, "$dir$file";
			if (exists $hashes{"$dir$file"})
				{
				print STDERR "FATAL: Duplicate Hash file $dir$file\n";
				fatal_error();
				return 1;
				}
			if (! -r "$dir$file")
				{
				print STDERR "FATAL: Can't access $dir$file\n";
				fatal_error();
				return 1;
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
		return 1;
		}

	if (@checked_hashes != @hashed_files)
		{
		print STDERR "FATAL: hash count incorrect\n";
		fatal_error();
		return 1;
		}

	foreach (@checked_hashes)
		{
		chomp;
		if (!(($file, $hash) = /^HMAC-SHA1\((.*)\)\s*=\s*(\w*)$/))
			{
			print STDERR "FATAL: Invalid syntax in file $fp\n";
			print STDERR "Line:\n$_\n";
			fatal_error();
			return 1;
			}
		if (length($hash) != 40)
			{
			print STDERR "FATAL: Invalid hash length for file $file\n";
			fatal_error();
			return 1;
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
		return 1;
		}

	if ($badfiles || $force_rewrite)
		{
		print "Updating Hash file $hash_file\n";
		if (!open(OUT, ">$hash_file"))
			{
			print STDERR "Error rewriting $hash_file";
			return 1;
			}
		print OUT "const char * const FIPS_source_hashes[] = {\n";
		foreach (@hashed_files)
			{
			print OUT "\"HMAC-SHA1($_)= $hashes{$_}\",\n";
			}
		print OUT "};\n";
		close OUT;
		}

	if (!$badfiles)
		{
		print "FIPS hash check successful\n";
		}

	return 0;

	}


sub fatal_error
	{
	print STDERR "*** Your source code does not match the FIPS validated source ***\n";
	}


