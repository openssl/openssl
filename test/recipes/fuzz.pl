# Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use Cwd qw/abs_path/;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_file result_file/;

# print logs
sub fuzz_dump_log {
    my ($log) = @_;
    return unless $ENV{HARNESS_VERBOSE} && open(my $fh, '<', $log);
    print STDERR <$fh>;
    close $fh;
}

# execute test and print backtrace
sub fuzz_print_backtrace {
    my ($f, $path, $point) = @_;
    my $bt_log = result_file("$f-backtrace.stderr.log");
    local $ENV{OPENSSL_TEST_MFAIL_BACKTRACE} = 1;
    local $ENV{OPENSSL_TEST_MFAIL_POINT} = $point if defined $point;
    # never limit the single file rerun used for diagnostics
    delete local $ENV{OPENSSL_TEST_CORPUS_MAX_TIME};
    delete local $ENV{OPENSSL_TEST_CORPUS_MAX_FILES};
    run(fuzz(["$f-test", $path], stderr => $bt_log));

    diag("- backtrace at injection point:");
    if (open(my $fh, '<', $bt_log)) {
        while (my $line = <$fh>) {
            chomp $line;
            diag("  $line");
        }
        close $fh;
    }
}

# check fuzz test logs
sub fuzz_check_log {
    my ($f, $log, $exit_ok, $silent_leak) = @_;

    my $has_leaks = 0;
    my $corpus_time = 0;
    my @tail;
    my ($last_path, $last_point);

    # collect info from the executed fuzz log
    if (open(my $fh, '<', $log)) {
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /^#\s/) {
                $corpus_time = $1
                    if $line =~ /^#\s*corpus_time:\s*([\d.]+)/;
                $last_path  = $1 if $line =~ /\bpath=(.+?)\s*$/;
                $last_point = $1 if $line =~ /\bpoint=(\d+)\//;
                @tail = ($line);
            } else {
                push @tail, $line;
                $has_leaks = 1
                    if $line =~ /^(?:Direct|Indirect) leak of \d+ byte/;
            }
        }
        close $fh;
    }

    # return if the test passed and there is no leak
    return (1, 0, $corpus_time) if $exit_ok && !$has_leaks;
    # return if there is a leak but it's silent (should not be reported)
    return (0, $has_leaks, $corpus_time) if $has_leaks && $silent_leak;

    # log leak info
    my $why = !$exit_ok ? "non-zero exit" : "leaks (clean exit)";
    diag("fuzz $f failed: $why");
    diag("- full stderr: $log");
    if (defined $last_path) {
        my $bin  = abs_path(bldtop_file('fuzz', "$f-test"));
        my $path = abs_path($last_path);
        my $env  = defined $last_point
            ? "OPENSSL_TEST_MFAIL_POINT=$last_point " : "";
        diag("- reproduce: $env$bin $path");
    }
    diag($_) for @tail;
    fuzz_print_backtrace($f, $last_path, $last_point)
        if defined $last_path && !$has_leaks;
    return (0, $has_leaks, $corpus_time);
}

# run fuzz test and dump logs
sub fuzz_run {
    my ($f, $d, $log_name, $silent_leak) = @_;
    my $log = result_file($log_name);
    my $exit_ok = run(fuzz(["$f-test", $d], stderr => $log));
    fuzz_dump_log($log);
    my ($passed, $leaks, $corpus_time) = fuzz_check_log($f, $log, $exit_ok,
                                                        $silent_leak);
    return ($passed, $leaks, $corpus_time, $log);
}

# run fuzz test in counting mode and no fail run
sub fuzz_run_count_only {
    my ($f, $d) = @_;
    my $log = result_file("$f-count.stderr.log");
    local $ENV{OPENSSL_TEST_MFAIL_COUNT_ONLY} = 1;
    my $exit_ok = run(fuzz(["$f-test", $d], stderr => $log));
    fuzz_dump_log($log);

    my ($corpus_time, $total, $cur, @allocs) = (0, 0, undef);
    if (open(my $fh, '<', $log)) {
        while (my $line = <$fh>) {
            $corpus_time = $1 if $line =~ /^#\s*corpus_time:\s*([\d.]+)/;
            $total = $1 if $line =~ /^#\s*corpus_files:\s*total=(\d+)/;
            $cur = $1 if $line =~ /^#\s*CORPUS_FILE\s+file_idx=(\d+)/;
            push @allocs, $1 + 0 if defined $cur
                && $line =~ /:\s*(\d+)\s+allocations\s*$/;
        }
        close $fh;
    }
    return ($exit_ok, $corpus_time, \@allocs, $total);
}

# find path and point of the reported leak for easy recreation
sub fuzz_mfail_bisect {
    my ($f, $log) = @_;

    # collect all paths and executed points from the output
    my (%path, %points);
    if (open(my $fh, '<', $log)) {
        while (my $line = <$fh>) {
            $path{$1} = $2
                if $line =~
                    /CORPUS_FILE\s+file_idx=(\d+)\s+size=\d+\s+path=(\S+)/;
            push @{$points{$1}}, $2
                if $line =~ /MFAIL_BEGIN\s+file_idx=(\d+)\s+point=(\d+)\/\d+/;
        }
        close $fh;
    }

    # reset current envs so they don't get used in bisect run
    delete local $ENV{OPENSSL_TEST_MFAIL_COUNT};
    delete local $ENV{OPENSSL_TEST_MFAIL_START};
    delete local $ENV{OPENSSL_TEST_MFAIL_POINT};
    delete local $ENV{OPENSSL_TEST_CORPUS_MAX_TIME};
    delete local $ENV{OPENSSL_TEST_CORPUS_MAX_FILES};

    diag("bisecting mfail leak across isolated point reruns");

    # go through all executed corpus files
    for my $idx (sort { $a <=> $b } keys %path) {
        # go trhout all executed points in path
        for my $p (@{$points{$idx} || []}) {
            local $ENV{OPENSSL_TEST_MFAIL_POINT} = $p;
            my $plog = result_file("$f-bisect-$idx-$p.stderr.log");
            my $exit_ok = run(fuzz(["$f-test", $path{$idx}], stderr => $plog),
                              quiet => 1);
            # silently skip runs without a leak
            my (undef, $leaks) = fuzz_check_log($f, $plog, $exit_ok, 1);
            next unless $leaks;
            # report exact leak location
            my $bin = abs_path(bldtop_file('fuzz', "$f-test"));
            my $abs = abs_path($path{$idx});
            diag("isolated leak: file_idx=$idx point=$p path=$path{$idx}");
            diag("- log: $plog");
            diag("- reproduce: OPENSSL_TEST_MFAIL_POINT=$p $bin $abs");
            fuzz_print_backtrace($f, $path{$idx}, $p);
            return;
        }
    }
    diag("bisection did not reproduce the leak");
}

# get all test_fuzz tests calling this
sub fuzz_test_names {
    my @names;
    for my $p (glob(srctop_dir('test', 'recipes') . '/[0-9][0-9]-test_fuzz_*.t')) {
        # push the actual name of the test used in TESTS filtering
        push @names, $1 if $p =~ m{/\d+-(test_fuzz_\S+)\.t$};
    }
    return @names;
}

# match a test name against TESTS env filter (test/run_tests.pl semantics)
sub fuzz_match_tests_filter {
    my ($name, $filter) = @_;
    return 1 unless defined $filter && $filter ne '';

    my @pats = grep { length } split /\s+/, $filter;
    return 1 unless @pats;

    # a leading negative implies a starting "alltests"
    my $included = $pats[0] =~ /^-/ ? 1 : 0;

    for my $pat (@pats) {
        # alltests resets the set to all, ignoring everything before
        if ($pat eq 'alltests') {
            $included = 1;
            next;
        }

        my $neg = $pat =~ s/^-//;

        # glob -> regex
        (my $re = quotemeta $pat) =~ s/\\\*/.*/g;
        $re =~ s/\\\?/./g;
        next unless $name =~ /\A$re\z/;

        $included = $neg ? 0 : 1;
    }

    return $included;
}

# get budget per test
sub fuzz_per_test_budget {
    my $budget = $ENV{OSSL_FUZZ_TEST_BUDGET} or return 0;
    my $jobs   = $ENV{OSSL_FUZZ_TEST_JOBS} || 1;
    my $filter = $ENV{TESTS};

    my @active = grep { fuzz_match_tests_filter($_, $filter) } fuzz_test_names();
    my $count  = scalar(@active) || 1;

    # we don't need all jobs if there are less tests
    $jobs = $count if $jobs > $count;

    my $per_test = $budget * $jobs / $count;
    diag(sprintf("budget=%ss jobs=%d active=%d -> per-test=%.3fs",
            $budget, $jobs, $count, $per_test));
    return $per_test;
}

# report when the run was cut short by the corpus time limit
sub fuzz_check_max_time {
    my ($f, $log) = @_;
    return unless open(my $fh, '<', $log);
    while (my $line = <$fh>) {
        if ($line =~ /^#\s*(CORPUS_MAX_TIME reached.*?)\s*$/) {
            diag("$f: $1");
            last;
        }
    }
    close $fh;
}

sub fuzz_ok {
    my ($f, %opts) = @_;
    my $d = srctop_dir('fuzz', 'corpora', $f);

    SKIP: {
        skip "No directory $d", 1 unless -d $d;

        my $per_test = fuzz_per_test_budget();
        my $safety = 0.8;
        my $target = $per_test * $safety;

        # no budget configured, just run the corpus
        unless ($per_test > 0) {
            ok(run(fuzz(["$f-test", $d])), "Fuzzing $f");
            return;
        }

        # probe a small evenly spread sample, selected by the test runner,
        # to estimate the per-file run time
        my ($ok, $probe_time, $allocs, $num_files);
        {
            local $ENV{OPENSSL_TEST_CORPUS_MAX_FILES} = 16;
            # bound the probe in case even its few files are too slow
            local $ENV{OPENSSL_TEST_CORPUS_MAX_TIME} =
                sprintf("%.3f", 0.25 * $target);
            ($ok, $probe_time, $allocs, $num_files) =
                fuzz_run_count_only($f, $d);
        }
        unless ($ok) {
            ok(0, "Fuzzing $f (count-only)");
            return;
        }

        # empty corpus, nothing to select, just run it as it is
        if ($num_files <= 0) {
            ok(run(fuzz(["$f-test", $d])), "Fuzzing $f");
            return;
        }

        # average over the files the probe managed to process
        my $probe_n = scalar @$allocs;
        $probe_n = 1 if $probe_n < 1;

        # get the maximum allocations in instance and count total
        my $total_allocs = 0;
        my $max_k = 0;
        for (@$allocs) {
            $total_allocs += $_;
            $max_k = $_ if $_ > $max_k;
        }
        diag(sprintf("%s: probe %d/%d files in %.3fs, allocs=%d, max=%d",
                $f, $probe_n, $num_files, $probe_time, $total_allocs, $max_k));

        # no allocations counted, can't size the mfail run
        if ($total_allocs <= 0) {
            ok(1, "Fuzzing $f (no allocations counted)");
            return;
        }

        # average per-file time; the clock may be too coarse to measure
        my $avg = $probe_time / $probe_n;
        $avg = 0.001 if $avg <= 0;
        my $remaining = $target - $probe_time;
        $remaining = 0 if $remaining < 0;

        # a file with count injections costs ~avg * (1 + count / 2), so
        # running mfail over n files fits: n * avg * (1 + count / 2) <= budget
        my $min_count = 3;
        my $use_n = $num_files;
        my $count = int(2 * ($remaining / ($avg * $num_files) - 1));
        if ($count < $min_count) {
            # budget too low for the whole corpus, drop some files instead
            $count = $min_count;
            $use_n = int($remaining / ($avg * (1 + $count / 2)));
            # always exercise mfail on at least one file
            ($use_n, $count) = (1, 1) if $use_n < 1;
        }
        # never exceed max(K_i); injections beyond that are wasted
        $count = $max_k if $count > $max_k;

        $use_n = $num_files if $use_n > $num_files;
        diag(sprintf("%s: running mfail on %d/%d files with count=%d",
                $f, $use_n, $num_files, $count));

        local $ENV{OPENSSL_TEST_MFAIL_COUNT} = $count;
        # the test runner selects an evenly spread subset of this size
        local $ENV{OPENSSL_TEST_CORPUS_MAX_FILES} = $use_n;
        # hard stop in case the probe estimate was too optimistic
        local $ENV{OPENSSL_TEST_CORPUS_MAX_TIME} =
            sprintf("%.3f", $remaining > 1 ? $remaining : 1);
        my $main_log = "$f-mfail.stderr.log";
        my ($passed, $leaks, undef, $log) = fuzz_run($f, $d, $main_log, 1);

        fuzz_check_max_time($f, $log);
        fuzz_mfail_bisect($f, $log) if !$passed && $leaks;
        ok($passed, sprintf("Fuzzing %s (mfail count=%d, files=%d/%d, "
                . "per-test=%.3fs)", $f, $count, $use_n, $num_files,
                $per_test));
    }
}

1;
