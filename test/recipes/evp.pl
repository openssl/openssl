# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Shared by the 30-test_evp*.t recipes that run evp_test on the data files
# in 30-test_evp_data.

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_file);
use OpenSSL::Test::Utils;

# evp_tests(files => [ ... ], default_files => [ ... ], extra => N)
#
# Runs evp_test on each of the files in |files| with the default provider
# and, if the FIPS module is built, with the FIPS provider, and on each of
# the files in |default_files| with the default provider only.  |extra| is
# the number of further tests the calling recipe runs itself.
sub evp_tests {
    my %args = @_;
    my @files = @{$args{files} // []};
    my @defltfiles = @{$args{default_files} // []};
    my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);
    my $no_legacy = disabled('legacy') || ($ENV{NO_LEGACY} // 0);

    # Default config depends on if the legacy module is built or not
    my $defaultcnf = $no_legacy ? 'default.cnf' : 'default-and-legacy.cnf';

    my @configs = ( $defaultcnf );
    # Only add the FIPS config if the FIPS module has been built
    push @configs, 'fips-and-base.cnf' unless $no_fips;

    plan skip_all => "No data files apply to this configuration"
        if !@files && !@defltfiles && !$args{extra};

    plan tests =>
        + (scalar(@configs) * scalar(@files))
        + scalar(@defltfiles)
        + ($args{extra} // 0);

    foreach (@configs) {
        my $conf = srctop_file("test", $_);

        foreach my $f ( @files ) {
            ok(run(test(["evp_test",
                         "-config", $conf,
                         srctop_file("test", "recipes", "30-test_evp_data",
                                     $f)])),
               "running evp_test -config $conf $f");
        }
    }

    my $conf = srctop_file("test", $defaultcnf);
    foreach my $f ( @defltfiles ) {
        ok(run(test(["evp_test",
                     "-config", $conf,
                     srctop_file("test", "recipes", "30-test_evp_data", $f)])),
           "running evp_test -config $conf $f");
    }
}

1;
