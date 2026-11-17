#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Config;
use Cwd qw(abs_path);
use IPC::Cmd;
use OpenSSL::Test;
use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file data_dir result_dir/;

setup("test_cmake_config");

plan skip_all => "cmake is not available"
    unless IPC::Cmd::can_run("cmake");

# Cross compiling the consumer project would require a toolchain
# file, which is a bigger endeavour than is fitting for this test.
plan skip_all => 'This is unsupported for cross compiled configurations'
    if config('CROSS_COMPILE');

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

# A fuzz build's static libraries carry the fuzzer compiler's
# instrumentation (__afl_area_ptr, __sanitizer_cov_trace_pc_guard_*),
# which a plain host-compiler consumer link cannot satisfy, just like
# the sanitizer runtimes above.
plan skip_all => "not run under fuzz instrumentation"
    if config('options') =~ /enable-fuzz-afl|enable-fuzz-libfuzzer/;

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

# Find out what generator cmake will use: $ENV{CMAKE_GENERATOR} when set,
# otherwise the default, which `cmake --system-information` reports.
my $cmake_generator = $ENV{CMAKE_GENERATOR};
if (!defined $cmake_generator) {
    foreach (`cmake --system-information`) {
        if (/^CMAKE_GENERATOR +"(.*?)"$/) {
            $cmake_generator = $1;
            last;
        }
    }
}
# Only the Visual Studio generators support platform selection (-A);
# other generators reject it with a hard error.  With those, the
# architecture is determined by the compiler that cmake finds in the
# environment instead.
my $platform_flag_ok =
    defined $cmake_generator && $cmake_generator =~ /Visual Studio/;

# With Visual Studio generators, cmake defaults to the x64 platform.
# The dummy programs must match the architecture of the OpenSSL build,
# so say it explicitly when it deviates from that default.
push @cmake_configure, "-A", "Win32"
    if config('target') =~ /^VC-WIN32/ && $platform_flag_ok;
push @cmake_configure, "-A", "ARM64"
    if config('target') =~ /^VC-WIN64-ARM/ && $platform_flag_ok;

# cmake defaults single-config builds with MSVC to Debug, which pulls in
# the debug CRT (msvcr*d.dll); minimal toolchain environments carry only
# the release CRT.  Build the consumer project in Release, like the
# OpenSSL build itself.  Multi-config generators ignore
# CMAKE_BUILD_TYPE; with those, the configuration is selected at build
# time (--config) instead.
push @cmake_configure, "-DCMAKE_BUILD_TYPE=Release"
    if config('target') =~ /^VC-/;

# A no-shared OpenSSL build links against the static CRT (Configurations
# sets /MT for that case); the dummy programs must use the same runtime,
# or they import msvcr*.dll, which a minimal toolchain environment need
# not carry.
push @cmake_configure, "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"
    if config('target') =~ /^VC-/ && disabled("shared");

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

# cmake and ctest are host tools; wrap.pl (run by OpenSSL::Test::run())
# would substitute the build's shared libraries into their processes
# where sonames match (such as 3.x trees, currently), breaking them when
# the ABIs differ. Only the dummy executables should be run through the
# wrapper (OPENSSL_WRAP_PL in the consumer project).
sub run_host_command {
    my ($command) = @_;
    my ($success, $error, $output) =
        IPC::Cmd::run(command => $command);
    if (!$success) {
        diag($error) if defined $error;
        diag(join("", @{$output})) if defined $output;
    }
    return $success;
}

ok(run_host_command(\@cmake_configure),
   "configure the cmake test project");
ok(run_host_command(["cmake", "--build", $cmake_build_dir, "--config", "Release"]),
   "build the cmake test project");
# Run a command and show its output whether it succeeds or not
sub run_diag_command {
    my ($command) = @_;
    my ($success, $error, $output) =
        IPC::Cmd::run(command => $command);
    diag(join("", @{$output})) if defined $output;
    diag($error) if !$success && defined $error;
}

# Diagnose a failing ctest run: show where the dummy binaries actually
# landed, and try running one directly, which discriminates "binary not
# where ctest looked for it" from "binary cannot be executed".
sub diagnose_cmake_build {
    my ($dir) = @_;

    diag("Contents of $dir:");
    diag("  $_") foreach sort glob("$dir/* $dir/*/*");
    # $Config{_exe} is the executable suffix on platforms that have one
    # ('.exe' on Windows, empty on Unix)
    my @exes = grep { -f $_ && !/\.(ilk|pdb|lib|exp)$/
                      && ($Config{_exe} eq '' || /\Q$Config{_exe}\E$/i) }
               glob("$dir/ossl_config_dummy_vars*"
                    . " $dir/*/ossl_config_dummy_vars*");
    if (@exes) {
        if ($^O eq 'MSWin32') {
            # Name what kills the binary: the effective PATH, and the
            # resolvability of the DLLs the binary imports.  The CRT
            # DLL names vary with the Visual Studio version
            # (msvcr120.dll for VS2013, vcruntime140.dll and
            # ucrtbase.dll for VS2015 and later), so take the list from
            # the binary itself rather than hard-coding it.
            run_diag_command(["cmd", "/c", "set", "PATH"]);
            my @imports;
            if (IPC::Cmd::can_run("dumpbin")) {
                my ($success, $error, $output) =
                    IPC::Cmd::run(command =>
                                  ["dumpbin", "/dependents", $exes[0]]);
                diag(join("", @{$output})) if defined $output;
                diag($error) if !$success && defined $error;
                if ($success) {
                    my %seen;
                    @imports =
                        grep { !$seen{lc $_}++ }
                        map { /^\s+(\S+\.dll)\s*$/i ? ($1) : () }
                        @{$output};
                }
            }
            if (@imports) {
                run_diag_command(["where", $_]) foreach @imports;
            } else {
                # dumpbin unavailable or failed; probe the CRT naming
                # patterns known to date
                run_diag_command(["where", "msvcr*.dll"]);
                run_diag_command(["where", "vcruntime*.dll"]);
                run_diag_command(["where", "ucrtbase.dll"]);
            }
        }
        diag("running $exes[0] directly:");
        run_host_command([$exes[0]]);
    } else {
        diag("no ossl_config_dummy_vars binary found");
    }
}

ok(run_host_command(["ctest", "--test-dir", $cmake_build_dir,
                     "-C", "Release", "--output-on-failure"]),
   "run the cmake test project")
    or diagnose_cmake_build($cmake_build_dir);
