package api_data;
use strict;

use Data::Dumper;
use File::Slurp;

# The basic data store for a declaration is a hash holding the following
# information (let's simply call this structure "declaration"):
# sym       => string (the symbol of the declaration)
# symcomment=> string (if there's a comment about this symbol) or undef
# type      => string (type definition text, with a '?' where the symbol should be
# kind      => 0 (variable)
#              1 (function)
# params    => list reference (list of declarations, one for each parameter)
#              [only exists when kind = 1]
# direction => 0 (input)
#              1 (output)
#              2 (input and output)
#              3 (output or input and output)
#              +4 (guess)
#              [only exists when this symbol is a parameter to a function]

# Constructor
sub new {
    my $class = shift;
    my $self = {};
    $self->{DECLARATIONS} = {};
    bless($self, $class);
    return $self;
}

sub read_declaration_db {
    my $self = shift;
    my $declaration_file = shift;
    my $buf = read_file($declaration_file);
    $self->{DECLARATIONS} = eval $buf;
    die $@ if $@;
}

sub write_declaration_db {
    my $self = shift;
    my $declaration_file = shift;

    $Data::Dumper::Purity = 1;
    open FILE,">".$declaration_file ||
	die "Can't open '$declaration_file': $!\n";
    print FILE "my ",Data::Dumper->Dump([ $self->{DECLARATIONS} ], [qw(declaration_db)]);
    close FILE;
}

sub insert_declaration {
    my $self = shift;
    my %decl = @_;
    my $sym = $decl{sym};

    if ($self->{DECLARATIONS}->{$sym}) {
	foreach my $k (('sym', 'symcomment','oldsym','objfile','kind')) {
	    $self->{DECLARATIONS}->{$sym}->{$k} = $decl{$k};
	}
	if ($self->{DECLARATIONS}->{$sym}->{kind} == 1) {
	    # Replace parameters only if the kind or type has changed
	    my $oldp = $self->{DECLARATIONS}->{$sym}->{params};
	    my $newp = $decl{params};
	    my $l = scalar(@{$oldp});
	    for my $pn (0..($l - 1)) {
		if ($oldp->[$pn]->{kind} != $newp->[$pn]->{kind}
		    || $oldp->[$pn]->{type} ne $newp->[$pn]->{type}) {
		    $self->{DECLARATIONS}->{$sym}->{params} = $newp;
		}
	    }
	}
    } else {
	$self->{DECLARATIONS}->{$decl{sym}} = { %decl };
    }
}

# Input is a simple C declaration, output is a declaration structure
sub _parse_declaration {
    my $decl = shift;
    my $newname = shift;
    my $objfile = shift;
    my $namecomment = shift;
    my %parsed_decl = ();

    my $debug = 0;

    print "DEBUG: going to parse: $decl\n" if $debug;

    # Start with changing all parens to { and } except the outermost
    # Within these, convert all commas to semi-colons
    my $s = "";
    do {
	print "DEBUG: decl: $decl\n" if $debug;
	$s = $decl;
	if ($decl =~ m/
		       \(
		         ([^\(\)]*)
		         \(
		           ([^\(\)]*)
		         \)
		     /x) {
	    print "DEBUG: \`: $`\n" if $debug;
	    print "DEBUG: 1: $1\n" if $debug;
	    print "DEBUG: 2: $2\n" if $debug;
	    print "DEBUG: \': $'\n" if $debug;

	    my $a = "$`"."("."$1";
	    my $b = "{"."$2"."}";
	    my $c = "$'";
	    print "DEBUG: a: $a\n" if $debug;
	    print "DEBUG: b: $b\n" if $debug;
	    print "DEBUG: c: $c\n" if $debug;
	    $b =~ s/,/;/g;
	    print "DEBUG: b: $b\n" if $debug;

	    $decl = $a.$b.$c;
	}
    } while ($s ne $decl);

    # There are types that we look for.  The first is the function pointer
    # T (*X)(...)
    if ($decl =~ m/
		   ^\s*
		   ([^\(]+)	# Return type of the function pointed at
		   \(
		     \s*\*\s*
		     ([^\)]*)	# Function returning or variable holding fn ptr
		   \)
		   \s*
		   \(
		     ([^\)]*)	# Parameter for the function pointed at
		   \)
		   \s*$
		 /x) {
	print "DEBUG: function pointer variable or function\n" if $debug;
	print "DEBUG:  1: $1\n" if $debug;
	print "DEBUG:  2: $2\n" if $debug;
	print "DEBUG:  3: $3\n" if $debug;

	my $tmp1 = $1 . "(*?)" . "(" . $3 . ")";
	my $tmp2 = $2;

	$tmp1 =~ tr/\{\}\;/(),/; # Convert all braces and semi-colons
				# back to parens and commas

	$tmp2 =~ tr/\{\}\;/(),/; # Convert all braces and semi-colons
				# back to parens and commas

	# Parse the symbol part with a fake type.  This will determine if
	# it's a variable or a function.
	my $subdeclaration = _parse_declaration("int " . $tmp2, $newname);
	map { $parsed_decl{$_} = $subdeclaration->{$_} } ( "sym",
							   "kind",
							   "params" );
	$parsed_decl{symcomment} = $namecomment if $namecomment;
	$parsed_decl{type} = $tmp1;
    }
    # If that wasn't it, check for the simple function declaration
    # T X(...)
    elsif ($decl =~ m/^\s*(.*?\W)(\w+)\s*\(\s*(.*)\s*\)\s*$/) {
	print "DEBUG: function\n" if $debug;
	print "DEBUG:  1: $1\n" if $debug;
	print "DEBUG:  2: $2\n" if $debug;
	print "DEBUG:  3: $3\n" if $debug;

	$parsed_decl{kind} = 1;
	$parsed_decl{type} = $1."?";
	$parsed_decl{sym} = $newname ? $newname : $2;
	$parsed_decl{symcomment} = $namecomment if $namecomment;
	$parsed_decl{oldsym} = $newname ? $2 : undef;
	$parsed_decl{params} = [
	    map { tr/\{\}\;/(),/; _parse_declaration($_,undef,undef,undef) }
	    grep { !/^\s*void\s*$/ }
	    split(/\s*,\s*/, $3)
	    ];
    }
    # If that wasn't it either, try to get a variable
    # T X or T X[...]
    elsif ($decl =~ m/^\s*(.*\W)(\w+)(\s*\[.*\])?\s*$/) {
	print "DEBUG: variable\n" if $debug;
	print "DEBUG:  1: $1\n" if $debug;
	print "DEBUG:  2: $2\n" if $debug;

	$parsed_decl{kind} = 0;
	$parsed_decl{type} = $1."?";
	$parsed_decl{sym} = $newname ? $newname : $2;
	$parsed_decl{symcomment} = $namecomment if $namecomment;
	$parsed_decl{oldsym} = $newname ? $2 : undef;
    }
    # Special for the parameter "..."
    elsif ($decl =~ m/^\s*\.\.\.\s*$/) {
	%parsed_decl = ( kind => 0, type => "?", sym => "..." );
    }
    # Otherwise, we got something weird
    else {
	print "Warning: weird declaration: $decl\n";
	%parsed_decl = ( kind => -1, decl => $decl );
    }
    $parsed_decl{objfile} = $objfile;

    print Dumper({ %parsed_decl }) if $debug;
    return { %parsed_decl };
}

sub add_declaration {
    my $self = shift;
    my $parsed = _parse_declaration(@_);
    $self->insert_declaration( %{$parsed} );
}

sub complete_directions {
    my $self = shift;
    foreach my $sym (keys %{$self->{DECLARATIONS}}) {
	if ($self->{DECLARATIONS}->{$sym}->{kind} == 1) {
	    map {
		if (!$_->{direction} || $_->{direction} =~ m/\?/) {
		    if ($_->{type} =~ m/const/) {
			$_->{direction} = '->'; # Input
		    } elsif ($_->{sym} =~ m/ctx/ || $_->{type} =~ m/ctx/i) {
			$_->{direction} = '<-?'; # Guess output
		    } elsif ($_->{type} =~ m/\*/) {
			if ($_->{type} =~ m/(short|int|char|size_t)/) {
			    $_->{direction} = '<-?'; # Guess output
			} else {
			    $_->{direction} = '<-? <->?'; # Guess output or input/output
			}
		    } else {
			$_->{direction} = '->'; # Input
		    }
		}
	    } @{$self->{DECLARATIONS}->{$sym}->{params}};
	}
    }
}

sub on_all_declarations {
    my $self = shift;
    my $fn = shift;
    foreach my $sym (sort keys %{$self->{DECLARATIONS}}) {
	&$fn($self->{DECLARATIONS}->{$sym});
    }
}

sub get_function_declaration_strings_from_file {
    my $fn = shift;
    my %declarations = ();
    my $line = "";
    my $cppline = "";

    my $debug = 0;

    foreach my $headerline (`cat $fn`) {
	chomp $headerline;
	print STDERR "DEBUG0: $headerline\n" if $debug;
	# First, treat the line at a CPP level; remove comments, add on more
	# lines if there's an ending backslash or an incomplete comment.
	# If none of that is true, then remove all comments and check if the
	# line starts with a #, skip if it does, otherwise continue.
	if ($cppline && $headerline) { $cppline .= " "; }
	$cppline .= $headerline;
	$cppline =~ s^\"(.|\\\")*\"^@@^g; # Collapse strings
	$cppline =~ s^/\*.*?\*/^^g;	  # Remove all complete comments
	print STDERR "DEBUG1: $cppline\n" if $debug;
	if ($cppline =~ m/\\$/) { # Keep on reading if the current line ends
				  # with a backslash
	    $cppline = $`;
	    next;
	}
	next if $cppline =~ m/\/\*/; # Keep on reading if there remains the
				     # start of a comment
	next if $cppline =~ m/"/;    # Keep on reading if there remains the
				     # start of a string
	if ($cppline =~ m/^\#/) {
	    $cppline = "";
	    next;
	}

	# Done with the preprocessor part, add the resulting line to the
	# line we're putting together to get a statement.
	if ($line && $cppline) { $line .= " "; }
	$line .= $cppline;
	$cppline = "";
	$line =~ s%extern\s+\@\@\s+\{%%g; # Remove 'extern "C" {'
	$line =~ s%\{[^\{\}]*\}%\$\$%g; # Collapse any compound structure
	print STDERR "DEBUG2: $line\n" if $debug;
	next if $line =~ m%\{%;	# If there is any compound structure start,
	# we are not quite done reading.
	$line =~ s%\}%%;		# Remove a lonely }, it's probably a rest
	# from 'extern "C" {'
	$line =~ s%^\s+%%;		# Remove beginning blanks
	$line =~ s%\s+$%%;		# Remove trailing blanks
	$line =~ s%\s+% %g;		# Collapse multiple blanks to one.
	if ($line =~ m/;/) {
	    print STDERR "DEBUG3: $`\n" if $debug;
	    my $decl = $`;	#`; # (emacs is stupid that way)
	    $line = $';		#'; # (emacs is stupid that way)

	    # Find the symbol by taking the declaration and fiddling with it:
	    # (remember, we're just extracting the symbol, so we're allowed
	    # to cheat here ;-))
	    # 1. Remove all paired parenthesies, innermost first.  While doing
	    #    this, if something like "(* foo)(" is found, this is a
	    #    function pointer; change it to "foo("
	    # 2. Remove all paired square parenthesies.
	    # 3. Remove any $$ with surrounding spaces.
	    # 4. Pick the last word, that's the symbol.
	    my $tmp;
	    my $sym = $decl;
	    print STDERR "DEBUG3.1: $sym\n" if $debug;
	    do {
		$tmp = $sym;
		# NOTE: The order of these two is important, and it's also
		# important not to use the g modifier.
		$sym =~ s/\(\s*\*\s*(\w+)\s*\)\s*\(/$1(/;
		$sym =~ s/\([^\(\)]*\)//;
		print STDERR "DEBUG3.2: $sym\n" if $debug;
	    } while ($tmp ne $sym);
	    do {
		$tmp = $sym;
		$sym =~ s/\[[^\[\]]*\]//g;
	    } while ($tmp ne $sym);
	    $sym =~ s/\s*\$\$\s*//g;
	    $sym =~ s/.*[\s\*](\w+)\s*$/$1/;
	    print STDERR "DEBUG4: $sym\n" if $debug;
	    if ($sym =~ m/\W/) {
		print STDERR "Warning[$fn]: didn't find proper symbol in declaration:\n";
		print STDERR "    decl: $decl\n";
		print STDERR "    sym:  $sym\n";
	    }
	    $declarations{$sym} = $decl;
	}
    }
    return %declarations;
}

1;
