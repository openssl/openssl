# Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;

sub fuzz_test {
    die "Only one argument accepted" if scalar @_ != 1;

    my $f = $_[0];
    my $d = srctop_dir('fuzz', 'corpora', $f);

    return run(fuzz(["$f-test", $d])) if -d $d;

    # Directory $d doesn't exist if we reach this point, so write a
    # diagnostic and return false.
    diag("No directory $d");
    return 0;
}

1;
