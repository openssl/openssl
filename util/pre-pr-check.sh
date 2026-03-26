#!/usr/bin/env bash
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# =============================================================================
# Pre-PR local checks (approximate GitHub CI) — see .github/workflows/ci.yml
#
# This branch / PR #30499 historically tripped several CI jobs. Those classes
# of failure are listed here so we extend this script instead of learning only
# from red GitHub checks:
#
# 1) basic_gcc, basic_clang, minimal, gcc-min-version, linux-arm64, etc.
#    - Wrong or incomplete base64 / PEM handling: widespread failures (EVP,
#      PEM, X509, decoder tests) because many stacks depend on EVP_Decode*.
#    - Fix: full make test (OSSL_RUN_CI_TESTS=1) on a clean tree; exercise
#      bio_base64 and PEM-heavy recipes.
#
# 2) address_ub_sanitizer (enable-asan enable-ubsan --debug full test suite)
#    - Heap overruns in optimized paths (e.g. SIMD writing past logical output
#      length) show up here, not in a plain release build.
#    - Fix: run this script with --with-asan-ci (out-of-tree build).
#
# 3) fuzz_tests (FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION + ASan/UBSan,
#    TESTS=test_fuzz*)
#    - Same memory safety issues often surface on fuzz corpora first (PEM
#      fuzzer drives base64 heavily).
#    - Fix: run --with-fuzz-ci (mirrors .github/workflows/ci.yml fuzz_tests).
#
# 4) check_update / check_docs
#    - Stale generated files or doc errors: make update + git diff, doc-nits.
#
# 5) Local-only / cross-build tree confusion
#    - test/p_test.so left from Linux (ELF) on macOS breaks prov_config_test
#      ("slice is not valid mach-o"). preflight_test_dso_warn catches common
#      cases.
#
# 6) Unintended scope (noise + labels)
#    - Touching providers/fips/*.c for unrelated edits triggers review labels;
#      warn_fips_scope_if_needed warns by default; use --no-fips-warn to skip.
#
# =============================================================================

set -eo pipefail

TOP="$(cd "$(dirname "$0")/.." && pwd)"
cd "$TOP"

JOBS="${PREPR_MAKE_JOBS:-4}"
HARNESS_JOBS="${HARNESS_JOBS:-4}"
LHASH_WORKERS="${LHASH_WORKERS:-16}"
CI_SUBMODULE_DEPTH="${CI_SUBMODULE_DEPTH:-1}"

WITH_DEMOS=1
RUN_DISTCLEAN=1
WITH_ASAN_CI=0
WITH_FUZZ_CI=0
WARN_FIPS_DIFF=1
SKIP_MAKE_TEST=0

usage() {
    cat <<'ENDUSAGE'
Usage: util/pre-pr-check.sh [options]

  Default: distclean, init fuzz/corpora, configure (strict-warnings, fips, lms),
           build, make update + git diff --exit-code, doc-nits, help, md-nits
           (if mdl), optional pre-commit, then make test (CI test set).

  --no-demos       Omit enable-demos enable-h3demo (avoids nghttp3 / demos).
  --no-distclean   Skip make distclean (faster; less like CI clean builds).
  --with-asan-ci   After main checks, run an out-of-tree build matching the
                   GitHub "address_ub_sanitizer" job (ASan+UBSan full tests).
  --with-fuzz-ci   After main checks, run an out-of-tree build matching the
                   GitHub "fuzz_tests" job (FUZZING_BUILD_MODE + test_fuzz*).
  --skip-make-test Skip the main make test (only build/update/doc checks).
  --no-fips-warn   Do not warn when the branch touches providers/fips/.
  -h, --help       This help.

Environment:
  PREPR_MAKE_JOBS      Parallel jobs for main and out-of-tree makes (default 4).
  PREPR_SKIP_PRECOMMIT Set non-empty to skip "pre-commit run --all-files".
  HARNESS_JOBS         Passed to "make test" (default 4); mirrors CI when unset.
  LHASH_WORKERS        Passed to "make test" (default 16).
  CI_SUBMODULE_DEPTH   Depth for "git submodule update --depth" on fuzz/corpora
                       (default 1; matches many CI checkouts).
  OPENSSL_TEST_RAND_ORDER  For the main in-tree "make test" only (default 0).
                       Out-of-tree ASan/fuzz steps always use 0 to match ci.yml.
                       The script always sets OSSL_RUN_CI_TESTS=1 for test runs.

Tips:
  Out-of-tree ASan/fuzz builds use _prepr_asan_build/ and _prepr_fuzz_build/
  under the repo root; they are gitignored when .gitignore includes those paths.
ENDUSAGE
}

for arg in "$@"; do
    case "$arg" in
        --no-demos) WITH_DEMOS=0 ;;
        --no-distclean) RUN_DISTCLEAN=0 ;;
        --with-asan-ci) WITH_ASAN_CI=1 ;;
        --with-fuzz-ci) WITH_FUZZ_CI=1 ;;
        --skip-make-test) SKIP_MAKE_TEST=1 ;;
        --no-fips-warn) WARN_FIPS_DIFF=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

preflight_test_dso_warn() {
    if [[ ! -f test/p_test.so ]] || ! command -v file >/dev/null 2>&1; then
        return 0
    fi
    local fs
    fs="$(file -b test/p_test.so || true)"
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Darwin)
            if echo "$fs" | grep -qi 'elf'; then
                echo "pre-pr-check: ERROR: test/p_test.so is ELF but this host is macOS." >&2
                echo "  prov_config_test loads ../test/p_test.so and will fail (invalid Mach-O)." >&2
                echo "  Remove it or symlink to test/p_test.dylib after building tests." >&2
                return 1
            fi
            ;;
        Linux)
            if echo "$fs" | grep -qi 'mach-o'; then
                echo "pre-pr-check: ERROR: test/p_test.so looks like Mach-O on Linux." >&2
                echo "  Remove the stale file and rebuild (make test will build the real .so)." >&2
                return 1
            fi
            ;;
    esac
    return 0
}

warn_fips_scope_if_needed() {
    [[ "$WARN_FIPS_DIFF" -eq 1 ]] || return 0
    local base=""
    for base in upstream/master origin/master; do
        if git rev-parse --verify "$base" >/dev/null 2>&1; then
            if git diff --name-only "$base"...HEAD 2>/dev/null | grep -qE '^providers/fips/'; then
                echo "pre-pr-check: WARNING: this branch touches providers/fips/ vs $base." >&2
                echo "  Expect extra review / CI labels on an OpenSSL PR unless FIPS changes are intended." >&2
            fi
            return 0
        fi
    done
}

submodule_fuzz_corpora() {
    git submodule update --init --depth "$CI_SUBMODULE_DEPTH" fuzz/corpora
}

run_make_test_ci() {
    OPENSSL_TEST_RAND_ORDER="${OPENSSL_TEST_RAND_ORDER:-0}" \
        OSSL_RUN_CI_TESTS=1 make test HARNESS_JOBS="$HARNESS_JOBS" \
        LHASH_WORKERS="$LHASH_WORKERS" "$@"
}

doc_and_meta_checks() {
    make doc-nits
    make help
    if command -v mdl >/dev/null 2>&1 \
        || PATH="${PATH}:$(ruby -e 'puts Gem.bindir' 2>/dev/null)" command -v mdl >/dev/null 2>&1; then
        make md-nits
    else
        echo "pre-pr-check: skipping md-nits (mdl not installed; try: gem install mdl)"
    fi
    if command -v pre-commit >/dev/null 2>&1 && [[ -z "${PREPR_SKIP_PRECOMMIT:-}" ]]; then
        pre-commit run --all-files
    elif [[ -z "${PREPR_SKIP_PRECOMMIT:-}" ]]; then
        echo "pre-pr-check: skipping pre-commit (not installed)"
    fi
}

main_build_and_test() {
    if [[ "$RUN_DISTCLEAN" -eq 1 ]]; then
        make distclean
    fi
    submodule_fuzz_corpora

    if [[ "$WITH_DEMOS" -eq 1 ]]; then
        ./config --strict-warnings --banner=Configured enable-fips enable-lms \
            enable-demos enable-h3demo && perl configdata.pm --dump
    else
        ./config --strict-warnings --banner=Configured enable-fips enable-lms \
            && perl configdata.pm --dump
    fi

    make build_generated
    make -s -j"$JOBS"

    make update
    git diff --exit-code

    doc_and_meta_checks

    if [[ "$SKIP_MAKE_TEST" -eq 1 ]]; then
        echo "pre-pr-check: skipping main make test (--skip-make-test)"
        return 0
    fi

    run_make_test_ci
}

# Mirrors .github/workflows/ci.yml job address_ub_sanitizer (Linux-oriented;
# may work on macOS with Clang).
asan_ci_tree() {
    local d="$TOP/_prepr_asan_build"
    echo "pre-pr-check: ASan CI mirror build in $d"
    rm -rf "$d"
    mkdir -p "$d"
    git -C "$TOP" submodule update --init --depth "$CI_SUBMODULE_DEPTH" fuzz/corpora
    (
        cd "$d"
        ../config --strict-warnings --banner=Configured --debug \
            enable-demos enable-h3demo \
            enable-asan enable-ec_explicit_curves enable-ubsan \
            enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
            enable-fips enable-lms \
            && perl configdata.pm --dump
        make -s -j"$JOBS"
        OSSL_RUN_CI_TESTS=1 make test HARNESS_JOBS="$HARNESS_JOBS" \
            LHASH_WORKERS="$LHASH_WORKERS" OPENSSL_TEST_RAND_ORDER=0
    )
}

# Mirrors .github/workflows/ci.yml job fuzz_tests (no FIPS in that job).
fuzz_ci_tree() {
    local d="$TOP/_prepr_fuzz_build"
    echo "pre-pr-check: fuzz_tests CI mirror build in $d"
    rm -rf "$d"
    mkdir -p "$d"
    git -C "$TOP" submodule update --init --depth "$CI_SUBMODULE_DEPTH" fuzz/corpora
    (
        cd "$d"
        ../config --strict-warnings --banner=Configured --debug \
            -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
            enable-asan enable-ec_explicit_curves enable-ubsan \
            enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
            enable-weak-ssl-ciphers enable-nextprotoneg \
            && perl configdata.pm --dump
        make -s -j"$JOBS"
        OSSL_RUN_CI_TESTS=1 make test HARNESS_JOBS="$HARNESS_JOBS" \
            LHASH_WORKERS="$LHASH_WORKERS" OPENSSL_TEST_RAND_ORDER=0 \
            TESTS='test_fuzz*'
    )
}

preflight_test_dso_warn
warn_fips_scope_if_needed
main_build_and_test

if [[ "$WITH_ASAN_CI" -eq 1 ]]; then
    asan_ci_tree
fi
if [[ "$WITH_FUZZ_CI" -eq 1 ]]; then
    fuzz_ci_tree
fi

echo "Pre-PR checklist passed."
