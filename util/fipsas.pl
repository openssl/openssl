
# FIPS assembly language preprocessor
# Renames all symbols in the file to
# their modified fips versions.


my @ARGS = @ARGV;

my $top = shift @ARGS;
my $target = shift @ARGS;

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

# Store all renames [noting minimal length].
my $minlen=0x10000;
while (<IN>)
	{
	if (/^#define\s+_?(\w+)\s+_?(\w+)\b/)
		{
		$edits{$1} = $2;
		my $len = length($1);
		$minlen = $len if ($len<$minlen);
		}
	}

open(IN,"$target") || die "Can't open $target for reading";

@code = <IN>;	# suck in whole file

close IN;

open(OUT,">$target") || die "Can't open $target for writing";

foreach $line (@code)
	{
	$line =~ s/\b(_?)(\w{$minlen,})\b/$1.($edits{$2} or $2)/geo;
	print OUT $line;
	}

close OUT;

if ($runasm)
	{
	# run assembler
	system @ARGS;

	my $rv = $?;

	die "Error executing assembler!" if $rv != 0;
	}
