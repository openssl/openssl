#! /usr/bin/perl

package with_fallback;

sub import {
    use File::Basename;
    use File::Spec::Functions;
    foreach (@_) {
	eval "require $_";
	if ($@) {
	    unshift @INC, catdir(dirname(__FILE__), "..", "external", "perl");
	    my $transfer = "transfer::$_";
	    eval "require $transfer";
	    shift @INC;
	    warn $@ if $@;
	}
    }
}
1;
