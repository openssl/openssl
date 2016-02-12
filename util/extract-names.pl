#!/usr/bin/perl

$/ = "";			# Eat a paragraph at once.
while(<STDIN>) {
    s|\R$||;
    s/\n/ /gm;
    if (/^=head1 /) {
	$name = 0;
    } elsif ($name) {
	if (/ - /) {
	    s/ - .*//;
	    s/,\s+/,/g;
	    s/\s+,/,/g;
	    s/^\s+//g;
	    s/\s+$//g;
	    s/\s/_/g;
	    push @words, split ',';
	}
    }
    if (/^=head1 *NAME *$/) {
	$name = 1;
    }
}

print join("\n", @words),"\n";

