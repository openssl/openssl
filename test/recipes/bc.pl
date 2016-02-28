#! /usr/bin/perl

use strict;
use warnings;

use Math::BigInt;

sub calc {
    @_ = __adder(@_);
    if (scalar @_ != 1) { return "NaN"; }
    return shift;
}

sub __canonhex {
    my ($sign, $hex) = (shift =~ /^([+\-]?)(.*)$/);
    $hex = "0x".$hex if $hex !~ /^0x/;
    return $sign.$hex;
}

sub __adder {
    @_ = __multiplier(@_);
    while (scalar @_ > 1 && $_[1] =~ /^[\+\-]$/) {
	my $operand1 = Math::BigInt->from_hex(__canonhex(shift));
	my $operator = shift;
	@_ = __multiplier(@_);
	my $operand2 = Math::BigInt->from_hex(__canonhex(shift));
	if ($operator eq "+") {
	    $operand1->badd($operand2);
	} elsif ($operator eq "-") {
	    $operand1->bsub($operand2);
	} else {
	    die "SOMETHING WENT AWFULLY WRONG";
	}
	unshift @_, $operand1->as_hex();
    }
    return @_;
}

sub __multiplier {
    @_ = __power(@_);
    while (scalar @_ > 1 && $_[1] =~ /^[\*\/%]$/) {
	my $operand1 = Math::BigInt->from_hex(__canonhex(shift));
	my $operator = shift;
	@_ = __power(@_);
	my $operand2 = Math::BigInt->from_hex(__canonhex(shift));
	if ($operator eq "*") {
	    $operand1->bmul($operand2);
	} elsif ($operator eq "/") {
	    $operand1->bdiv($operand2);
	} elsif ($operator eq "%") {
	    # Here's a bit of a quirk...
	    # With OpenSSL's BN, as well as bc, the result of -10 % 3 is -1
	    # while Math::BigInt, the result is 2.
	    # The latter is mathematically more correct, but...
	    my $o1isneg = $operand1->is_neg();
	    $operand1->babs();
	    # Math::BigInt does something different with a negative modulus,
	    # while OpenSSL's BN and bc treat it like a positive number...
	    $operand2->babs();
	    $operand1->bmod($operand2);
	    if ($o1isneg) { $operand1->bneg(); }
	} else {
	    die "SOMETHING WENT AWFULLY WRONG";
	}
	unshift @_, $operand1->as_hex();
    }
    return @_;
}

sub __power {
    @_ = __paren(@_);
    while (scalar @_ > 1 && $_[1] eq "^") {
	my $operand1 = Math::BigInt->from_hex(__canonhex(shift));
	shift;
	@_ = __paren(@_);
	my $operand2 = Math::BigInt->from_hex(__canonhex(shift));
	$operand1->bpow($operand2);
	unshift @_, $operand1->as_hex();
    }
    return @_;
}

# returns array ( $result, @remaining )
sub __paren {
    if (scalar @_ > 0 && $_[0] eq "(") {
	shift;
	my @result = __adder(@_);
	if (scalar @_ == 0 || $_[0] ne ")") {
	    return ("NaN");
	}
	shift;
	return @result;
    }
    return @_;
}

1;
