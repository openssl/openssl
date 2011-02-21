
# Filter script. Take all FIPS object files from the environment
# and print out only those in the given directory.

my $dir = $ARGV[0];

my $asmobjs = "";

# Add any needed assembly language files.

$asmobjs = $ENV{AES_ENC} if $dir eq "aes";
$asmobjs = $ENV{BN_ASM} if $dir eq "bn";
$asmobjs = $ENV{DES_ENC} if $dir eq "des";
$asmobjs = $ENV{SHA1_ASM_OBJ} if $dir eq "sha";
$asmobjs = $ENV{MODES_ASM_OBJ} if $dir eq "modes";

# Get all other FIPS object files, filtered by directory.

my @objlist = grep {/crypto\/$dir\//} split / /, $ENV{FIPS_EX_OBJ};

push @objlist, split / /, $asmobjs;

# Fatal error if no matches
die "No objects in $dir!" if (scalar @objlist == 0);

# Output all matches removing pathname.
foreach (@objlist)
	{
	s|../crypto/$dir/||;
	print "$_\n";
	}
