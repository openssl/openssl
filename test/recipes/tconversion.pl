#! /usr/bin/env perl
# Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Compare qw/compare_text/;
use File::Copy;
use OpenSSL::Test qw/:DEFAULT/;
use Time::Piece;
use POSIX qw(strftime);

my %conversionforms = (
    # Default conversion forms.  Other series may be added with
    # specific test types as key.
    "*"		=> [ "d", "p" ],
    "msb"	=> [ "d", "p", "msblob" ],
    "pvk"	=> [ "d", "p", "pvk" ],
    );
sub tconversion {
    my %opts = @_;

    die "Missing option -type" unless $opts{-type};
    die "Missing option -in" unless $opts{-in};
    my $testtype = $opts{-type};
    my $t = $opts{-in};
    my $prefix = $opts{-prefix} // $testtype;
    my @conversionforms =
	defined($conversionforms{$testtype}) ?
	@{$conversionforms{$testtype}} :
	@{$conversionforms{"*"}};
    my @openssl_args;
    if (defined $opts{-args}) {
        @openssl_args = @{$opts{-args}} if ref $opts{-args} eq 'ARRAY';
        @openssl_args = ($opts{-args}) if ref $opts{-args} eq '';
    }
    @openssl_args = ($testtype) unless @openssl_args;

    my $n = scalar @conversionforms;
    my $totaltests =
	1			# for initializing
	+ $n			# initial conversions from p to all forms (A)
	+ $n*$n			# conversion from result of A to all forms (B)
	+ 1			# comparing original test file to p form of A
	+ $n*($n-1);		# comparing first conversion to each form in A with B
    $totaltests-- if ($testtype eq "p7d"); # no comparison of original test file
    $totaltests -= $n if ($testtype eq "pvk"); # no comparisons of the pvk form
    plan tests => $totaltests;

    my @cmd = ("openssl", @openssl_args);

    my $init;
    if (scalar @openssl_args > 0 && $openssl_args[0] eq "pkey") {
	$init = ok(run(app([@cmd, "-in", $t, "-out", "$prefix-fff.p"])),
		   'initializing');
    } else {
	$init = ok(copy($t, "$prefix-fff.p"), 'initializing');
    }
    if (!$init) {
	diag("Trying to copy $t to $prefix-fff.p : $!");
    }

  SKIP: {
      skip "Not initialized, skipping...", 22 unless $init;

      foreach my $to (@conversionforms) {
	  ok(run(app([@cmd,
		      "-in", "$prefix-fff.p",
		      "-inform", "p",
		      "-out", "$prefix-f.$to",
		      "-outform", $to])),
	     "p -> $to");
      }

      foreach my $to (@conversionforms) {
	  foreach my $from (@conversionforms) {
	      ok(run(app([@cmd,
			  "-in", "$prefix-f.$from",
			  "-inform", $from,
			  "-out", "$prefix-ff.$from$to",
			  "-outform", $to])),
		 "$from -> $to");
	  }
      }

      if ($testtype ne "p7d") {
	  is(cmp_text("$prefix-fff.p", "$prefix-f.p"), 0,
	     'comparing orig to p');
      }

      foreach my $to (@conversionforms) {
	  next if $to eq "d" or $to eq "pvk";
	  foreach my $from (@conversionforms) {
	      is(cmp_text("$prefix-f.$to", "$prefix-ff.$from$to"), 0,
		 "comparing $to to $from$to");
	  }
      }
    }
}

sub cmp_text {
    return compare_text(@_, sub {
        $_[0] =~ s/\R//g;
        $_[1] =~ s/\R//g;
        return $_[0] ne $_[1];
    });
}

sub file_contains {
    my ($file, $pattern) = @_;
    open(DATA, $file) or return 0;
    $_= join('', <DATA>);
    close(DATA);
    s/\s+/ /g; # take multiple whitespace (including newline) as single space
    return m/$pattern/ ? 1 : 0;
}

sub test_file_contains {
    my ($desc, $file, $pattern, $expected) = @_;
    $expected //= 1;
    return is(file_contains($file, $pattern), $expected,
       "$desc should ".($expected ? "" : "not ")."contain '$pattern'");
}

sub cert_contains {
    my ($cert, $pattern, $expected, $name) = @_;
    my $out = "cert_contains.out";
    run(app(["openssl", "x509", "-noout", "-text", "-in", $cert, "-out", $out]));
    return test_file_contains(($name ? "$name: " : "").$cert, $out, $pattern, $expected);
    # not unlinking $out
}

sub cert_contains_all {
    my ($cert, @patterns) = @_;
    my $out = "cert_contains.out";
    my $pattern;
    run(app(["openssl", "x509", "-noout", "-text", "-in", $cert, "-out", $out]));
    foreach $pattern (@patterns) {
        if(!test_file_contains(("").$cert, $out, $pattern, 1)) {
            return 0;
        }
    }
    # not unlinking $out
    return 1;
}

sub has_version {
    my ($cert, $expect) = @_;
    cert_contains($cert, "Version: $expect", 1);
}

sub has_SKID {
    my ($cert, $expect) = @_;
    cert_contains($cert, "Subject Key Identifier", $expect);
}

sub has_AKID {
    my ($cert, $expect) = @_;
    cert_contains($cert, "Authority Key Identifier", $expect);
}

sub uniq (@) {
    my %seen = ();
    grep { not $seen{$_}++ } @_;
}

sub file_n_different_lines {
    my $filename = shift @_;
    open(DATA, $filename) or return 0;
    chomp(my @lines = <DATA>);
    close(DATA);
    return scalar(uniq @lines);
}

sub cert_ext_has_n_different_lines {
    my ($cert, $expected, $exts, $name) = @_;
    my $out = "cert_n_different_exts.out";
    run(app(["openssl", "x509", "-noout", "-ext", $exts,
             "-in", $cert, "-out", $out]));
    is(file_n_different_lines($out), $expected, ($name ? "$name: " : "").
       "$cert '$exts' output should contain $expected different lines");
    # not unlinking $out
}

# extracts string value of certificate field from a -text formatted-output
sub get_field {
    my ($f, $field) = @_;
    my $string = "";
    open my $fh, $f or die;
    while (my $line = <$fh>) {
        if ($line =~ /$field:\s+(.*)/) {
            $string = $1;
        }
    }
    close $fh;
    return $string;
}

sub get_issuer {
    return get_field(@_, "Issuer");
}

sub get_not_before {
    return get_field(@_, "Not Before");
}

# Date as yyyy-mm-dd
sub get_not_before_date {
    return Time::Piece->strptime(
        get_not_before(@_),
        "%b %d %T %Y %Z")->date;
}

sub get_not_after {
    return get_field(@_, "Not After ");
}

# Date as yyyy-mm-dd
sub get_not_after_date {
    return Time::Piece->strptime(
        get_not_after(@_),
        "%b %d %T %Y %Z")->date;
}

1;
