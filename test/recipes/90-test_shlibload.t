#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test qw/:DEFAULT bldtop_dir/;
use OpenSSL::Test::Utils;

#Load configdata.pm

BEGIN {
    setup("test_shlibload");
}
use lib bldtop_dir('.');
use configdata;

plan skip_all => "Test only supported in a shared build" if disabled("shared");
plan skip_all => "Test is disabled on AIX" if config('target') =~ m|^aix|;

plan tests => 4;

my $sover_filename = config('shlib_version_number');
$sover_filename =~ s|\.|_|g
    if config('target') =~ /^(?:VC-|mingw)/;
$sover_filename =~ sprintf "%02d%02d", split(/\./, $sover_filename)
    if config('target') =~ /^vms-/;
sub sharedname {
    my $lib = shift;
    return undef if $disabled{shared} || $lib =~ /\.a$/;
    if (config('target') =~ m|^VC-|) {
        $lib .= "-$sover_filename" . $target{multilib};
    } elsif (config('target') =~ /^Cygwin/) {
        $lib =~ s|^lib|cyg|;
        $lib .= "-$sover_filename";
    } elsif (config('target') =~ /^mingw/) {
        $lib .= "-$sover_filename";
        $lib .= "-x64" if config('target') eq "mingw64";
    }
    return $lib;
}

my $libcrypto = sharedname('libcrypto').$target{shared_extension_simple};
my $libssl = sharedname('libssl').$target{shared_extension_simple};

ok(run(test(["shlibloadtest", "-crypto_first", $libcrypto, $libssl])),
   "running shlibloadtest -crypto_first");
ok(run(test(["shlibloadtest", "-ssl_first", $libcrypto, $libssl])),
   "running shlibloadtest -ssl_first");
ok(run(test(["shlibloadtest", "-just_crypto", $libcrypto, $libssl])),
   "running shlibloadtest -just_crypto");
ok(run(test(["shlibloadtest", "-dso_ref", $libcrypto, $libssl])),
   "running shlibloadtest -dso_ref");

