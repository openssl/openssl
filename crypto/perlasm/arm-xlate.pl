#!/usr/bin/env perl

# ARM assembler distiller by <appro>.

my $flavour = shift;
my $output = shift;
open STDOUT,">$output" || die "can't open $output: $!";

$flavour = "linux32" if (!$flavour or $flavour eq "void");

my %GLOBALS;
my $dotinlocallabels=($flavour=~/linux/)?1:0;

################################################################
# directives which need special treatment on different platforms
################################################################
my $arch = sub {
    if ($flavour =~ /linux/)	{ ".arch\t".join(',',@_); }
    else			{ ""; }
};
my $globl = sub {
    my $name = shift;
    my $global = \$GLOBALS{$name};
    my $ret;

    SWITCH: for ($flavour) {
	/ios/		&& do { $name = "_$name";
				last;
			      };
    }

    $ret = ".globl	$name" if (!$ret);
    $$global = $name;
    $ret;
};
my $global = $globl;
my $extern = sub {
    &$globl(@_);
    return;	# return nothing
};
my $type = sub {
    if ($flavour =~ /linux/)	{ ".type\t".join(',',@_); }
    else			{ ""; }
};
my $size = sub {
    if ($flavour =~ /linux/)	{ ".size\t".join(',',@_); }
    else			{ ""; }
};
my $inst = sub {
    if ($flavour =~ /linux/)    { ".inst\t".join(',',@_); }
    else                        { ".long\t".join(',',@_); }
};
my $asciz = sub {
    my $line = join(",",@_);
    if ($line =~ /^"(.*)"$/)
    {	".byte	" . join(",",unpack("C*",$1),0) . "\n.align	2";	}
    else
    {	"";	}
};

sub range {
  my ($r,$sfx,$start,$end) = @_;

    join(",",map("$r$_$sfx",($start..$end)));
}

sub parse_args {
  my $line = shift;
  my @ret = ();

    pos($line)=0;

    while (1) {
	if ($line =~ m/\G\[/gc) {
	    $line =~ m/\G([^\]]+\][^,]*)\s*/g;
	    push @ret,"[$1";
	}
	elsif ($line =~ m/\G\{/gc) {
	    $line =~ m/\G([^\}]+\}[^,]*)\s*/g;
	    my $arg = $1;
	    $arg =~ s/([rdqv])([0-9]+)([^\-]*)\-\1([0-9]+)\3/range($1,$3,$2,$4)/ge;
	    push @ret,"{$arg";
	}
	elsif ($line =~ m/\G([^,]+)\s*/g) {
	    push @ret,$1;
	}

	last if ($line =~ m/\G$/gc);

	$line =~ m/\G,\s*/g;
    }

    map {my $s=$_;$s=~s/\b(\w+)/$GLOBALS{$1} or $1/ge;$s} @ret;
}

while($line=<>) {

    $line =~ s|/\*.*\*/||;	# get rid of C-style comments...
    $line =~ s|^\s+||;		# ... and skip white spaces in beginning...
    $line =~ s|\s+$||;		# ... and at the end

    {
	$line =~ s|[\b\.]L(\w+)|L$1|g;	# common denominator for Locallabel
	$line =~ s|\bL(\w+)|\.L$1|g	if ($dotinlocallabels);
    }

    {
	$line =~ s|(^[\.\w]+)\:\s*||;
	my $label = $1;
	if ($label) {
	    printf "%s:",($GLOBALS{$label} or $label);
	}
    }

    if ($line !~ m/^#/o) {
	$line =~ s|^\s*(\.?)(\S+)\s*||o;
	my $c = $1; $c = "\t" if ($c eq "");
	my $mnemonic = $2;
	my $opcode;
	if ($mnemonic =~ m/([^\.]+)\.([^\.]+)/o) {
	    $opcode = eval("\$$1_$2");
	} else {
	    $opcode = eval("\$$mnemonic");
	}

	my @args=parse_args($line);

	if (ref($opcode) eq 'CODE') {
		$line = &$opcode(@args);
	} elsif ($mnemonic)         {
		$line = $c.$mnemonic;
		$line.= "\t".join(',',@args) if ($#args>=0);
	}
    }

    print $line if ($line);
    print "\n";
}

close STDOUT;
