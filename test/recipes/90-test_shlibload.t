#! /usr/bin/env perl
# Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

use Opentls::Test qw/:DEFAULT srctop_dir bldtop_dir/;
use Opentls::Test::Utils;
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
my $libtls = platform->sharedlib('libtls');

(my $fh, my $filename) = tempfile();
ok(run(test(["shlibloadtest", "-crypto_first", $libcrypto, $libtls, $filename])),
   "running shlibloadtest -crypto_first $filename");
ok(check_atexit($fh));
unlink $filename;
($fh, $filename) = tempfile();
ok(run(test(["shlibloadtest", "-tls_first", $libcrypto, $libtls, $filename])),
   "running shlibloadtest -tls_first $filename");
ok(check_atexit($fh));
unlink $filename;
($fh, $filename) = tempfile();
ok(run(test(["shlibloadtest", "-just_crypto", $libcrypto, $libtls, $filename])),
   "running shlibloadtest -just_crypto $filename");
ok(check_atexit($fh));
unlink $filename;
($fh, $filename) = tempfile();
ok(run(test(["shlibloadtest", "-dso_ref", $libcrypto, $libtls, $filename])),
   "running shlibloadtest -dso_ref $filename");
ok(check_atexit($fh));
unlink $filename;
($fh, $filename) = tempfile();
ok(run(test(["shlibloadtest", "-no_atexit", $libcrypto, $libtls, $filename])),
   "running shlibloadtest -no_atexit $filename");
ok(!check_atexit($fh));
unlink $filename;

sub check_atexit {
    my $fh = shift;
    my $data = <$fh>;

    return 1 if (defined $data && $data =~ m/atexit\(\) run/);

    return 0;
}
