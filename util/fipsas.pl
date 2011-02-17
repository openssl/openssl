
# FIPS assembly language preprocessor
# Renames all symbols in the file to
# their modified fips versions.


my @ARGS = @ARGV;

my $top = shift @ARGS;
my $target = shift @ARGS;

# HACK to disable operation if no OPENSSL_FIPSSYMS option.
# will go away when tested more fully.

my $enabled = 0;

foreach (@ARGS) { $enabled = 1 if /-DOPENSSL_FIPSSYMS/ ; }

if ($enabled == 0)
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

#rename target temporarily
rename($target, "tmptarg.s") || die "Can't rename $target\n";

#edit target
open IN,"tmptarg.s";
open OUT, ">$target";

while (<IN>)
{
	while (($from, $to) = each %edits)
		{
		s/(\b)$from(\b)/$1$to$2/g;
		}
	print OUT $_;
}
# run assembler
system @ARGS;

my $rv = $?;

# restore target
unlink $target;
rename "tmptarg.s", $target;

die "Error executing assembler!" if $rv != 0;

