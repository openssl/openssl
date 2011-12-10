
# FIPS assembly language preprocessor
# Renames all symbols in the file to
# their modified fips versions.


my @ARGS = @ARGV;

my $top = shift @ARGS;
my $target = shift @ARGS;
my $tmptarg = $target;

$tmptarg =~ s/\.[^\\\/\.]+$/.tmp/;

my $runasm = 1;

if ($ARGS[0] eq "norunasm")
	{
	$runasm = 0;
	shift @ARGS;
	}

my $enabled = 0;

$enabled = 1 if $ENV{FIPSCANISTERINTERNAL} eq "y";

if ($enabled == 0 && $runasm)
	{
	system @ARGS;
	exit $?
	}


# Open symbol rename file.
open(IN, "$top/fips/fipssyms.h") || die "Can't open fipssyms.h";

# Skip to assembler symbols
while (<IN>)
	{
	last if (/assembler/)
	}

# Store all renames.
while (<IN>)
	{
	if (/^#define\s+(\w+)\s+(\w+)\b/)
		{
		$edits{$1} = $2;
		}
	}

my ($from, $to);

#delete any temp file lying around

unlink $tmptarg;

#rename target temporarily
rename($target, $tmptarg) || die "Can't rename $target";

#edit target
open(IN,$tmptarg) || die "Can't open temporary file";
open(OUT, ">$target") || die "Can't open output file $target";

while (<IN>)
{
	while (($from, $to) = each %edits)
		{
		s/(\b_*)$from(\b)/$1$to$2/g;
		}
	print OUT $_;
}

close OUT;

if ($runasm)
	{
	# run assembler
	system @ARGS;

	my $rv = $?;

	# restore target
	unlink $target;
	rename $tmptarg, $target;

	die "Error executing assembler!" if $rv != 0;
	}
else
	{
	# Don't care about target
	unlink $tmptarg;
	}
