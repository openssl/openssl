#!/usr/bin/perl

$/ = "";			# Eat a paragraph at once.
while(<STDIN>) {
    chop;
    s/\n/ /gm;
    if (/^=head1 /) {
	$name = 0;
    } elsif ($name) {
	if (/ - /) {
	    s/ - .*//;
	    s/[ \t,]+/ /g;
	    push @words, split ' ';
	}
    }
    if (/^=head1 *NAME *$/) {
	$name = 1;
    }
}

print join("\n", @words),"\n";

