#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);

#Load configdata.pm

BEGIN {
    setup("test_shlibload");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a shared build" if disabled("shared");
plan skip_all => "Test is disabled on AIX" if config('target') =~ m|^aix|;
plan skip_all => "Test only supported in a dso build" if disabled("dso");

plan tests => 10;

my $libcrypto = platform->sharedlib('libcrypto');
my $libssl = platform->sharedlib('libssl');

sub run_shlibloadtest {
    my $atexit = shift;
    (my $fh, my $filename) = tempfile();
    ok(run(test(["shlibloadtest", @_, $libcrypto, $libssl, $filename])),
       join(' ', ("running shlibloadtest", @_,"$filename")));
    cmp_ok(check_atexit($fh), '==', $atexit,
           "checking that 'atexit()' ".($atexit ? "was" : "wasn't")." run");
    unlink $filename;
}

# Each run_shlibloadtest runs two tests
run_shlibloadtest(1, "-crypto_first");
run_shlibloadtest(1, "-ssl_first");
run_shlibloadtest(1, "-just_crypto");
 SKIP: {
     skip "Skipping -dso_ref, not supported on this platform", 2
         if config('target') =~ m|^Cygwin|;
     run_shlibloadtest(1, "-dso_ref");
}
run_shlibloadtest(0, "-no_atexit");

sub check_atexit {
    my $fh = shift;
    my $data = <$fh>;

    return 1 if (defined $data && $data =~ m/atexit\(\) run/);

    return 0;
}
