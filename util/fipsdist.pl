
# FIPS distribution filter.
# Takes tarball listing and removes unnecessary files and directories.
#


my $objs = "";
foreach (split / /, "FIPS_EX_OBJ AES_ENC BN_ASM DES_ENC SHA1_ASM_OBJ MODES_ASM_OBJ")
	{
	$objs .= " $ENV{$_}";
	}

my $noec2m = 0;


my @objlist = split / /, $objs;

foreach (@objlist) { $tarobjs{"$1.c"} = 1 if /([^\/]+).o$/};

$tarobjs{"ncbc_enc.c"} = 1;
$tarobjs{"mem_clr.c"} = 1;
$tarobjs{"ppccap.c"} = 1;
$tarobjs{"sparcv9cap.c"} = 1;
$tarobjs{"armcap.c"} = 1;

foreach (split / /, $ENV{LINKDIRS} ) { $cdirs{$_} = 1 };

$cdirs{perlasm} = 1;

$noec2m = 1 if (exists $ENV{NOEC2M});

if ($noec2m)
	{
	delete $tarobjs{"bn_gf2m.c"};
	delete $tarobjs{"ec2_mult.c"};
	delete $tarobjs{"ec2_smpl.c"};
	}

my %keep =
	(
	"Makefile.fips" => 1,
	"Makefile.shared" => 1,
	"README.FIPS" => 1,
	"README.ECC" => 1,
	"e_os.h" => 1,
	"e_os2.h" => 1,
	"Configure" => 1,
	"config" => 1,
	);

while (<STDIN>)
	{
	chomp;
	# Keep top level files in list
	if (!/\// && -f $_)
		{
		next unless exists $keep{$_};
		}
	else
		{
		next unless (/^(fips\/|crypto|util|test|include|ms)/);
		}
	if (/^crypto\/([^\/]+)/)
		{
		# Skip unused directories under crypto/
		next if -d "crypto/$1" && !exists $cdirs{$1};
		# Skip GF2m assembly language perl scripts
		next if $noec2m && /gf2m\.pl/;
		next if /vpaes-\w*\.pl/;
		# Keep assembly language dir, Makefile or certain extensions
		if (!/\/asm\// && !/\/Makefile$/ && !/\.(in|pl|h|S)$/)
			{
			# If C source file must be on list.
			next if !/(\w+\.c)$/ || !exists $tarobjs{$1};
			}
		}
	if (/^test\//)
		{
		next unless /Makefile/ || /dummytest.c/;
		}
	print "$_\n";
	}
exit 1;
