
# FIPS distribution filter. 
# Takes tarball listing and removes unnecessary files and directories.
#


my $objs = "";
foreach (split / /, "FIPS_EX_OBJ AES_ENC BN_ASM DES_ENC SHA1_ASM_OBJ MODES_ASM_OBJ")
	{
	$objs .= " $ENV{$_}";
	}


my @objlist = split / /, $objs;

foreach (@objlist) { $tarobjs{"$1.c"} = 1 if /([^\/]+).o$/};

$tarobjs{"ncbc_enc.c"} = 1;

foreach (split / /, $ENV{LINKDIRS} ) { $cdirs{$_} = 1 };

$cdirs{perlasm} = 1;

foreach (keys %cdirs) { print STDERR "CDIR: $_\n";}

while (<STDIN>)
	{
	chomp;
	# Skip directories but leave top level files.
	next unless (/^(fips\/|crypto|util|test|include)/ || (!/\// && -f $_));
	if (/^crypto\/([^\/]+)/)
		{
		# Skip unused directories under crypto/
		next if -d "crypto/$1" && !exists $cdirs{$1};
		# Keep assembly language dir, Makefile or certain extensions
		if (!/\/asm\// && !/\/Makefile$/ && && !/\.(in|pl|h)$/)
			{
			# If C source file must be on list.
			next if !/(\w+\.c)$/ || !exists $tarobjs{$1};
			}
		}
	print "$_\n";
	}
exit 1;
