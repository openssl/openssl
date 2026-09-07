#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Cwd qw(abs_path);
use IPC::Cmd;
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file data_dir result_dir/;

setup("test_cmake_config");

plan skip_all => "cmake is not available"
    unless IPC::Cmd::can_run("cmake");

# The cmake-built dummies aren't sanitizer-instrumented, but wrap.pl
# inherits the sanitizer runtime environment from the outer test run.
# ASan refuses to attach to a non-instrumented executable, MSan
# produces spurious link errors against the sanitized libraries, and
# a static UBSan build leaves the consumer link without the UBSan
# runtime (__ubsan_handle_* symbols).
plan skip_all => "not run under address sanitizer"
    unless disabled("asan");
plan skip_all => "not run under memory sanitizer"
    unless disabled("msan");
plan skip_all => "not run under undefined behavior sanitizer"
    unless disabled("ubsan");

# We require cmake 3.22 or later
my $cmake_version_output = `cmake --version`;
my ($cmake_major, $cmake_minor) =
    $cmake_version_output =~ /version (\d+)\.(\d+)/;
plan skip_all => "cmake version could not be determined"
    unless defined $cmake_major;
plan skip_all => "cmake 3.22 or later is required (found $cmake_major.$cmake_minor)"
    unless $cmake_major > 3 || ($cmake_major == 3 && $cmake_minor >= 22);

plan tests => 3;

my $cmake_build_dir = result_dir("cmake-build");

my @cmake_configure =
    ("cmake",
     "-S", abs_path(data_dir()),
     "-B", $cmake_build_dir,
     # Point find_package() at the build tree's exported config
     "-DCMAKE_PREFIX_PATH=" . abs_path(bldtop_dir()),
     # The dummy programs are run through the same wrapper that the rest
     # of the test suite uses, so the loader path is set up for them
     "-DOPENSSL_WRAP_PL=" . abs_path(bldtop_file("util", "wrap.pl")));
# With Visual Studio generators, cmake defaults to the x64 platform.
# The dummy programs must match the architecture of the OpenSSL build,
# so say it explicitly when it deviates from that default.
push @cmake_configure, "-A", "Win32"
    if config('target') =~ /^VC-WIN32/;
push @cmake_configure, "-A", "ARM64"
    if config('target') =~ /^VC-WIN64-ARM/;

# With Unix generators, cmake compiles the consumer project with the
# host compiler's default word size, which may deviate from the OpenSSL
# build's (e.g. linux-x86 on an x86_64 host).  Translate the word size
# and ABI selectors from the OpenSSL build's own flags, much like the
# -A platform selection above.  An arch selector may come from the
# target's flags or from user supplied ones.
my @flag_tokens = map { split(/\s+/, $_) } (target('cflags') // '',
                                            target('CFLAGS') // '',
                                            @{config('cflags') // []},
                                            @{config('CFLAGS') // []});
my @abi_cflags;
while (@flag_tokens) {
    my $token = shift @flag_tokens;
    if ($token =~ /^(-m(?:31|32|64|x32)|-mabi=.*|-maix(?:32|64)|-q(?:32|64)|-xarch=.*|\+DD(?:32|64))$/) {
        # cmake passes CMAKE_C_FLAGS on the C link line as well
        push @abi_cflags, $token;
    } elsif ($token eq '-arch' && @flag_tokens) {
        # Darwin; the Xcode generator requires the dedicated setting
        push @cmake_configure,
            "-DCMAKE_OSX_ARCHITECTURES=" . shift @flag_tokens;
    }
}
push @cmake_configure, "-DCMAKE_C_FLAGS=" . join(" ", @abi_cflags)
    if @abi_cflags;

push @cmake_configure, "-DTEST_LEGACY_PROVIDER=OFF"
    if disabled("legacy") || disabled("module");

ok(run(cmd([@cmake_configure])),
   "configure the cmake test project");
ok(run(cmd(["cmake", "--build", $cmake_build_dir, "--config", "Release"])),
   "build the cmake test project");
ok(run(cmd(["ctest", "--test-dir", $cmake_build_dir,
            "-C", "Release", "--output-on-failure"])),
   "run the cmake test project");
