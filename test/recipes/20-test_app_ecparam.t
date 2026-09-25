#! /usr/bin/env perl
# Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Copy;
use File::Compare qw/compare_text compare/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_app_ecparam");

plan skip_all => "EC or EC2M isn't supported in this build"
    if disabled("ec") || disabled("ec2m");

# The parameter corpus belongs to 15-test_ecparam.t, so it has to be named
# by path rather than through data_file(), which resolves against the data
# directory of the recipe that calls it.
sub param_file {
    return srctop_file("test", "recipes", "15-test_ecparam_data", @_);
}

# The parameter corpus is swept in process by 15-test_ecparam.t.  What is
# tested here is the applications: their options, and that they write what
# they read.  A representative curve is enough for that; running the whole
# corpus through them buys process startup rather than coverage.
my $named = param_file('valid', 'secp384r1-named.pem');
my $explicit = param_file('valid', 'secp384r1-explicit.pem');
my $prime = param_file('valid', 'prime256v1-named.pem');

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);

plan tests => 8;

sub checkcompare {
    my $files = shift; # List of files
    my $app = shift;   # Which application

    foreach (@$files) {
        my $testout = "$app.tst";

        ok(run(app(['openssl', $app, '-out', $testout, '-in', $_])));
        ok(!compare_text($_, $testout, sub {
            my $in1 = $_[0];
            my $in2 = $_[1];
            $in1 =~ s/\r\n/\n/g;
            $in2 =~ s/\r\n/\n/g;
            $in1 ne $in2}), "Original file $_ is the same as new one");
    }
}

sub check_identical {
    my $apps = shift; # List of applications

    foreach (@$apps) {
        my $inout = "$_.tst";
        my $backup = "backup.tst";

        copy($inout, $backup);
        ok(run(app(['openssl', $_, '-in', $inout, '-out', $inout])));
        ok(!compare($inout, $backup), "converted file $inout did not change");
    }
}

my @representative = ($named, $explicit, $prime);

subtest "Check ecparam does not change the parameter file on output" => sub {
    plan tests => 2 * scalar(@representative);
    checkcompare(\@representative, "ecparam");
};

subtest "Check pkeyparam does not change the parameter file on output" => sub {
    plan tests => 2 * scalar(@representative);
    checkcompare(\@representative, "pkeyparam");
};

my @apps = ("ecparam", "pkeyparam");
subtest "Check param apps do not garble infile identical to outfile" => sub {
    plan tests => 2 * scalar(@apps);
    check_identical(\@apps);
};

subtest "Check loading of fips and non-fips params" => sub {
    plan skip_all => "FIPS is disabled"
        if $no_fips;
    plan tests => 8;

    my $fipsconf = srctop_file("test", "fips-and-base.cnf");
    my $defaultconf = srctop_file("test", "default.cnf");

    $ENV{OPENSSL_CONF} = $fipsconf;

    ok(run(app(['openssl', 'ecparam',
                '-in', param_file('valid', 'secp384r1-explicit.pem'),
                '-check'])),
       "Loading explicitly encoded valid curve");

    ok(run(app(['openssl', 'ecparam',
                '-in', param_file('valid', 'secp384r1-named.pem'),
                '-check'])),
       "Loading named valid curve");

    ok(!run(app(['openssl', 'ecparam',
                '-in', param_file('valid', 'secp112r1-named.pem'),
                '-check'])),
       "Fail loading named non-fips curve");

    ok(!run(app(['openssl', 'pkeyparam',
                '-in', param_file('valid', 'secp112r1-named.pem'),
                '-check'])),
       "Fail loading named non-fips curve using pkeyparam");

    ok(run(app(['openssl', 'ecparam',
                '-provider', 'default',
                '-propquery', '?fips!=yes',
                '-in', param_file('valid', 'secp112r1-named.pem'),
                '-check'])),
       "Loading named non-fips curve in FIPS mode with non-FIPS property".
       " query");

    ok(run(app(['openssl', 'pkeyparam',
                '-provider', 'default',
                '-propquery', '?fips!=yes',
                '-in', param_file('valid', 'secp112r1-named.pem'),
                '-check'])),
       "Loading named non-fips curve in FIPS mode with non-FIPS property".
       " query using pkeyparam");

    ok(!run(app(['openssl', 'ecparam',
                '-genkey', '-name', 'secp112r1'])),
       "Fail generating key for named non-fips curve");

    ok(run(app(['openssl', 'ecparam',
                '-provider', 'default',
                '-propquery', '?fips!=yes',
                '-genkey', '-name', 'secp112r1'])),
       "Generating key for named non-fips curve with non-FIPS property query");

    $ENV{OPENSSL_CONF} = $defaultconf;
};

subtest "Check ecparam -param_enc converts between named and explicit" => sub {
    plan tests => 3;

    # The encodings are canonical, so re-encoding a named curve as explicit
    # (and vice versa) must reproduce the matching reference file byte for byte.
    my $to_explicit = 'param-explicit.tst';
    ok(run(app(['openssl', 'ecparam', '-in', $named, '-param_enc', 'explicit',
                '-out', $to_explicit]))
       && !compare($to_explicit, $explicit),
       "named_curve params re-encoded as explicit match the reference file");

    my $to_named = 'param-named.tst';
    ok(run(app(['openssl', 'ecparam', '-in', $explicit, '-param_enc',
                'named_curve', '-out', $to_named]))
       && !compare($to_named, $named),
       "explicit params re-encoded as named_curve match the reference file");

    ok(!run(app(['openssl', 'ecparam', '-in', $named, '-noout',
                 '-param_enc', 'bogus'])),
       "an invalid parameter encoding is rejected");
};

subtest "Check ecparam -inform and -outform handling" => sub {
    plan tests => 4;

    my $der = 'param.der';
    ok(run(app(['openssl', 'ecparam', '-in', $named, '-outform', 'DER',
                '-out', $der])),
       "write DER-encoded parameters");
    my $pem = 'param-der.pem';
    ok(run(app(['openssl', 'ecparam', '-inform', 'DER', '-in', $der,
                '-out', $pem]))
       && !compare($pem, $named),
       "parameters survive a PEM -> DER -> PEM roundtrip");

    ok(!run(app(['openssl', 'ecparam', '-in', $der, '-noout'])),
       "DER input without -inform is rejected as the default is PEM");

    ok(!run(app(['openssl', 'ecparam', '-in', $named, '-outform', 'MSBLOB',
                 '-out', 'param.tmp'])),
       "-outform is limited to PEM and DER");
};

subtest "Check ecparam -conv_form selects the generator point encoding" => sub {
    plan tests => 5;

    # Only explicit parameters encode the generator point; the reference file
    # uses the default uncompressed form.
    my $comp = 'param-comp.pem';
    ok(run(app(['openssl', 'ecparam', '-in', $explicit, '-conv_form',
                'compressed', '-out', $comp])),
       "write explicit parameters with a compressed generator");
    ok((-s $comp) < (-s $explicit),
       "compressed generator encoding is smaller than uncompressed");

    my $back = 'param-unc.pem';
    ok(run(app(['openssl', 'ecparam', '-in', $comp, '-conv_form',
                'uncompressed', '-out', $back]))
       && !compare($back, $explicit),
       "converting back to uncompressed matches the reference file");

    my $namedout = 'param-named-conv.pem';
    ok(run(app(['openssl', 'ecparam', '-in', $named, '-conv_form',
                'compressed', '-out', $namedout]))
       && !compare($namedout, $named),
       "-conv_form does not change named curve parameters");

    ok(!run(app(['openssl', 'ecparam', '-in', $named, '-noout',
                 '-conv_form', 'bogus'])),
       "an invalid conversion form is rejected");
};

subtest "Check ecparam -text and -list_curves" => sub {
    plan tests => 7;

    # Named parameters print the curve identification.
    my @named = run(app(['openssl', 'ecparam', '-text', '-noout', '-in', $named],
                        stderr => undef),
                    capture => 1);
    chomp @named;
    ok(grep(/^EC-Parameters: \(384 bit field, 192 bit security level\)$/, @named),
       "named parameters print the EC-Parameters header");
    ok(grep(/^ASN1 OID: secp384r1$/, @named),
       "named parameters print the expected curve OID");
    ok(grep(/^NIST CURVE: P-384$/, @named),
       "named parameters print the expected NIST curve name");

    # Explicit parameters print the field parameters instead of the curve name.
    my @explicit = run(app(['openssl', 'ecparam', '-text', '-noout',
                            '-in', $explicit],
                           stderr => undef),
                       capture => 1);
    chomp @explicit;
    ok(grep(/^EC-Parameters: \(384 bit field, 192 bit security level\)$/, @explicit),
       "explicit parameters print the EC-Parameters header");
    ok(grep(/^Field Type: prime-field$/, @explicit)
       && grep(/^Cofactor:/, @explicit),
       "explicit parameters print the field parameters");
    ok(!grep(/^ASN1 OID:/, @explicit),
       "explicit parameters do not print a curve OID");

    ok(run(app(['openssl', 'ecparam', '-list_curves'])), "Test -list_curves");
};
