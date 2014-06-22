#!/bin/env perl
#
# Quick and dirty utility to help assemble the mandated (but otherwise
# useless) API documentation. We get the list of external function
# symbols from fipscanister.o, pair those with the source file names
# (from ./fips/fipssyms.h), and map to the object file name containing
# them.
#
# Requires the "nm" and "find" utilities.
# Execure from the root of the FIPS module source code workarea

use HTML::Entities;
use File::Basename;

$here = dirname($0);
require "$here/api_fns.pm";

$_direction_question = ''; # Set to '?' to show "<-?", "<->?" for uncertain directions

print STDERR "Info: finding FIPS renames and reimplementations of OpenSSL symbols\n";
# Get mapping of old (source code) to new (live as renamed) symbols
foreach $file ("./fips/fipssyms.h") {
    open(IN, $file) || die "Error opening $file";
    # grab pairs until assembler symbols
    my $buf = '';
    my $reimplementations = 1;	# When 1, we're looking at reimplementations
				# (not renames) of OpenSSL functions.  They
				# still have to be saved to get the API.
    while (<IN>) {
	$reimplementations = 0 if m|^\s*/\*\sRename\ssymbols\s|;

	if ($buf) {
	    $_ = $buf . $_;
	    $buf = '';
	}
	if (s/\\\n$//) {
	    $buf = $_;
	    next;
	}
	if (m/\(/) {
	    ($oldname, $newname) = m/#define\s+(\S+)\(.*\)\s+(\S+)\(.*\)/;
	} else {
	    ($oldname, $newname) = m/#define\s+(\S+)\s+(\S+)/;
	}

	$oldname || next;
	if (!$reimplementations) {
	    $oldname{$newname} = $oldname;
	}
	$oldimpl{$newname} = $oldname;
	last if (/assembler/)
    }
    close(IN);
    # %oldname is the mapping of new function names to old
    print "<!-- Total of ", scalar(keys %oldname), " mapped symbols in $file -->\n";
}

print STDERR "Info: finding FIPS symbols in object files\n";
# generate list of external function names in fipscanister.o
$file = "./fips/fipscanister.o";
for (`nm -g --defined-only -p -o $file`) {
    chomp;
    s/^\S+ T // || next;
    m/^fips_/ && next;
    $fipssyms{$_}++;
    $objname =~ s/\.o$/\.\[o\|c\]/;
    $objname{$symname} = $objname;
}
# keys %fipssyms is the list of module functions
print "<!-- Total of ", scalar(keys %fipssyms), " functions in $file -->\n";

# grab filename to symbol name mapping, each line is of the format
#	./fips/sha/fips_sha1_selftest.o:00000000 T FIPS_selftest_sha1
# discard the offset and type ":00000000 T".
for (`find . -name '*.o' \\! -name 'fipscanister.o' -exec nm -g --defined-only -p -o {} \\;`) {
        ($objname, $symname) = m/^(\S+):\S+\s+T+\s+(\S+)/;
        $objname || next;
#	$fipssyms{$symname} || next;
	$objname =~ s/\.o$/\.\[o\|c\]/;
        $objname{$symname} = $objname;
        }
# %objname is the mapping of new symbol name to (source/object) file name
print "<!-- Total of ", scalar(keys %objname), " functions found in files -->\n";

print STDERR "Info: finding declarations in header files\n";

# grab filenames in include/openssl, run each of them through
# get_function_declarations_from_file (defined in api_fns.pl)
# and collect the result.
%declarations = ();
while (<include/openssl/*.h ./crypto/cryptlib.h>) {
    my %decls = api_data::get_function_declaration_strings_from_file($_);
    map { $declarations{$_} = $decls{$_} } keys %decls;
}
# %declarations is the mapping of old symbol name to their declaration
print "<!-- Total of ", scalar(keys %declarations), " declarations found in header files -->\n";

# Add the markers FIPS_text_start and FIPS_text_end
$declarations{FIPS_text_start} = "void *FIPS_text_start()";
$declarations{FIPS_text_end} = "void *FIPS_text_end()";


# Read list of API names obtained from edited "nm -g fipscanister.o"
$spill = 0;
sub printer {
    foreach (@_) {
	if ($_->{kind} >= 0) {
	    if ($spill) {
		print " " x $indent;
		print "kind:     ",$_->{kind} ? "function" : "variable","\n";
		print " " x $indent;
		print "sym:      ",$_->{sym},"\n";
		print " " x $indent;
		print "type:     ",$_->{type},"\n";
	    }
	    if ($_->{kind}) {
		$c = 0;
		map {
		    if ($spill) {
			print " " x $indent;
			printf "param %d:\n", ++$c;
		    }
		    $indent += 2;
		    printer($_);
		    my $direction = $_->{direction};
		    if (!$_direction_question) {
			$direction =~ s/<-\? <->\?/<->/;
			$direction =~ s/\?//g;
		    }
		    print " " x $indent,$direction," ",$_->{sym},"\n";
		    $indent -= 2;
		} @{$_->{params}};
		if ($_->{type} !~ m/^\s*void\s*$/) {
		    print " " x $indent;
		    print "<- Return\n";
		}
	    }
	} else {
	    if ($spill) {
		print " " x $indent;
		print "decl:     ",$_->{decl},"\n";
	    }
	}
    }
}

sub html_printer {
    my $print_mode = shift;	# 0 = print declaration with symbol in bold,
				#     call recursively with 1 for each parameter,
				#     call recursively with 2 for each parameter
				# 1 = print declaration with sym grey background,
				#     call recursivelt with 3 for each parameter
				# 2 = just print declaration
    my $d = shift;		# Parsed declaration
    my $s = '';

    if ($print_mode == 0) {
	$d->{sym} || return $s;
	my $h = "<hr><br />\n";
	$h .= $d->{sym} . ($d->{symcomment} ? " " . $d->{symcomment} : "");
	$h .= " in file " . $d->{objfile} . "<br />\n<br />\n";

	$s .= '<b>' . $d->{sym} . '</b>';
	if ($d->{kind} == 1) {
	    $s .= '(';
	    $s .= join(', ',
		       map {
			   html_printer(1,$_);
		       } @{$d->{params}});
	    $s .= ')';
	}
	my $t = $d->{type};
	$t =~ s/\?/$s/;
	$s = $t;
	if ($d->{kind} == 1) {
	    map {
		my $direction = $_->{direction};
		if (!$_direction_question) {
		    $direction =~ s/<-\? <->\?/<->/;
		    $direction =~ s/\?//g;
		}
		$s .= "<br />\n";
		$s .= encode_entities($direction
				      . "\xA0" x (9 - length($direction)));
		$s .= $_->{sym};
	    } @{$d->{params}};
	}
	if ($d->{type} !~ m/^\s*void\s*\?$/) {
	    $s .= "<br />\n";
	    $s .= encode_entities('<-'.("\xA0" x 7).'Return');
	}
	$s = $h . $s;
    } elsif ($print_mode == 1) {
	$s .= '<span style="background: #c0c0c0">' . $d->{sym} . '</span>';
	if ($d->{kind} == 1) {
	    $s .= '(';
	    $s .= join(', ',
		       map {
			   html_printer(3,$_);
		       } @{$d->{params}});
	    $s .= ')';
	}
	my $t = $d->{type};
	$t =~ s/\?/$s/;
	$s = $t;
    } elsif ($print_mode == 2) {
	$s .= $d->{sym};
	if ($d->{kind} == 1) {
	    $s .= '(';
	    $s .= join(', ',
		       map {
			   html_printer(2,$_);
		       } @{$d->{params}});
	    $s .= ')';
	}
	my $t = $d->{type};
	$t =~ s/\?/$s/;
	$s = $t;
    }
    return $s;
}

print STDERR "Info: building/updating symbol information database\n";

$d = api_data->new();
if (-s "$here/declarations.dat") {
    $d->read_declaration_db("$here/declarations.dat");
} else {
    print STDERR "Warning: there was no file '$here/declarations.dat'.  A new one will be created\n";
}

for (sort keys %fipssyms) {
    $newname = $_;
    $namecomment = undef;
    if ($oldname{$newname}) {
	$oldname = $oldname{$newname};
	$objname = $objname{$oldname} ? $objname{$oldname} : $objname{$newname};
	$namecomment = "(renames $oldname)";
    } else {
	$objname = $objname{$newname};
    }
    if ($oldimpl{$newname}) {
	$apisym = $oldimpl{$newname};
	$namecomment = "(reimplements $apisym)" if !$namecomment;
    } else {
	$apisym = $newname;
    }
    $declaration = $declarations{$apisym};
    print "<!--\n";
    print "$newname\t\t$namecomment\tin file $objname:\n";
    print "  ",$declaration,"\n  ";
    $d->add_declaration($declaration,$newname,$objname,$namecomment);
    print "-->\n";
}

$d->complete_directions();
$d->write_declaration_db("$here/declarations.dat");

print STDERR "Info: printing output\n";

$d->on_all_declarations(
    sub {
	my $decl = shift;
	#$indent = 2;
	#print printer($decl);
	print "<p>",html_printer(0,$decl),"</p>\n";
    });
