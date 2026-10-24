/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Given a list of files, run each of them through the fuzzer.  Note that
 * failure will be indicated by some kind of crash. Switching on things like
 * asan improves the test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "fuzzer.h"
#include "internal/o_dir.h"
#include "mfail.h"

#if defined(_WIN32) && defined(_MAX_PATH) && !defined(PATH_MAX)
#define PATH_MAX _MAX_PATH
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if !defined(S_ISREG)
#define S_ISREG(m) ((m) & S_IFREG)
#endif

static double secs_since(clock_t start)
{
    return (double)(clock() - start) / CLOCKS_PER_SEC;
}

static clock_t corpus_start;
static double corpus_max_time;

/* stop starting new work once the corpus time limit has passed */
static int corpus_max_time_hit(void)
{
    return corpus_max_time > 0
        && secs_since(corpus_start) >= corpus_max_time;
}

static void run_baseline(const unsigned char *buf, size_t s)
{
    FuzzerTestOneInput(buf, s);
}

static void run_mfail(const unsigned char *buf, size_t s,
    const char *path, int file_idx)
{
    mfail_init(file_idx, MFAIL_FLAG_COUNT);
    while (!corpus_max_time_hit() && mfail_has_next()) {
        if (mfail_get_phase() == MFAIL_PHASE_COUNTING)
            fprintf(stderr,
                "# MFAIL_BEGIN file_idx=%d phase=count\n", file_idx);
        else
            fprintf(stderr,
                "# MFAIL_BEGIN file_idx=%d point=%d/%d\n",
                file_idx, mfail_get_point(), mfail_get_total());

        mfail_start();
        FuzzerTestOneInput(buf, s);
        mfail_end();

        if (mfail_get_phase() == MFAIL_PHASE_COUNTING) {
            fprintf(stderr, "# %s: %d allocations\n", path, mfail_get_count());
        } else {
            fprintf(stderr, "# %s: point %d/%d %s\n", path,
                mfail_get_point(), mfail_get_total(),
                mfail_was_triggered() ? "hit" : "unreached");
        }
        ERR_clear_error();
    }
}

static void testfile(const char *pathname, int file_idx)
{
    struct stat st;
    FILE *f;
    unsigned char *buf;
    size_t s;

    if (stat(pathname, &st) < 0 || !S_ISREG(st.st_mode))
        return;

    fprintf(stderr, "# CORPUS_FILE file_idx=%d size=%lld path=%s\n",
        file_idx, (long long)st.st_size, pathname);
    f = fopen(pathname, "rb");
    if (f == NULL)
        return;
    buf = malloc(st.st_size);
    if (buf == NULL) {
        fclose(f);
        return;
    }
    s = fread(buf, 1, st.st_size, f);
    OPENSSL_assert(s == (size_t)st.st_size);

    if (mfail_is_installed())
        run_mfail(buf, s, pathname, file_idx);
    else
        run_baseline(buf, s);

    free(buf);
    fclose(f);
}

static char **corpus_paths;
static int corpus_total;
static int corpus_capacity;

static int corpus_add(const char *pathname)
{
    char *copy;
    struct stat st;

    /* only collect regular files */
    if (stat(pathname, &st) < 0 || !S_ISREG(st.st_mode))
        return 1;

    if (corpus_total >= corpus_capacity) {
        int capacity = corpus_capacity > 0 ? corpus_capacity * 2 : 64;
        char **paths = realloc(corpus_paths, capacity * sizeof(*paths));

        if (paths == NULL)
            return 0;
        corpus_paths = paths;
        corpus_capacity = capacity;
    }
    copy = malloc(strlen(pathname) + 1);
    if (copy == NULL)
        return 0;
    strcpy(copy, pathname);
    corpus_paths[corpus_total++] = copy;
    return 1;
}

/* collect the file or all the directory entries the argument points to */
static int corpus_collect(const char *arg)
{
    size_t dirname_len = strlen(arg);
    const char *filename = NULL;
    char *pathname = NULL;
    OPENSSL_DIR_CTX *ctx = NULL;
    int wasdir = 0;
    int ok = 1;

    /*
     * We start with trying to read the given path as a directory.
     */
    while (ok && (filename = OPENSSL_DIR_read(&ctx, arg)) != NULL) {
        wasdir = 1;
        if (pathname == NULL) {
            pathname = malloc(PATH_MAX);
            if (pathname == NULL)
                break;
            strcpy(pathname, arg);
#ifdef __VMS
            if (strchr(":<]", pathname[dirname_len - 1]) == NULL)
#endif
                pathname[dirname_len++] = '/';
            pathname[dirname_len] = '\0';
        }
        strcpy(pathname + dirname_len, filename);
        ok = corpus_add(pathname);
    }
    OPENSSL_DIR_end(&ctx);

    /* If it wasn't a directory, treat it as a file instead */
    if (ok && !wasdir)
        ok = corpus_add(arg);

    free(pathname);
    return ok;
}

static int corpus_path_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int main(int argc, char **argv)
{
    int n, mfi_rc, bits, selected, chosen, skipped;
    unsigned int i, r, v;
    int file_idx = 0;
    const char *max_time_env = getenv("OPENSSL_TEST_CORPUS_MAX_TIME");
    const char *max_files_env = getenv("OPENSSL_TEST_CORPUS_MAX_FILES");
    int max_files = 0;

    if (max_time_env != NULL && *max_time_env != '\0') {
        corpus_max_time = strtod(max_time_env, NULL);
        if (corpus_max_time < 0)
            corpus_max_time = 0;
    }
    if (max_files_env != NULL && *max_files_env != '\0') {
        max_files = (int)strtol(max_files_env, NULL, 10);
        if (max_files < 0)
            max_files = 0;
    }

    mfi_rc = mfail_install(1);
    if (mfi_rc < 0) {
        fprintf(stderr, "mfail: failed to install allocator hooks\n");
        return 1;
    } else if (mfi_rc > 0) {
        /* Disable buffering for better crash analysis */
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }

    if (FuzzerInitialize(&argc, &argv) < 0) {
        if (mfail_is_installed())
            return 0; /* init failure under mfail is expected */
        return 1;
    }

    for (n = 1; n < argc; ++n) {
        if (!corpus_collect(argv[n])) {
            fprintf(stderr, "failed to collect corpus files\n");
            return 1;
        }
    }
    if (corpus_total > 1)
        qsort(corpus_paths, corpus_total, sizeof(*corpus_paths),
            corpus_path_cmp);

    selected = corpus_total;
    if (max_files > 0 && max_files < selected)
        selected = max_files;

    corpus_start = clock();

    /*
     * Walk the sorted list in bit reversed index order so that both the
     * selection and a possible time limit cut keep the processed files
     * evenly spread over the whole corpus.
     */
    bits = 0;
    while ((1 << bits) < corpus_total)
        bits++;
    chosen = 0;
    skipped = 0;
    for (i = 0; chosen < selected && i < (1U << bits); i++) {
        for (r = 0, v = i, n = 0; n < bits; n++, v >>= 1)
            r = (r << 1) | (v & 1);
        if (r >= (unsigned int)corpus_total)
            continue;
        chosen++;
        if (corpus_max_time_hit()) {
            skipped++;
            continue;
        }
        testfile(corpus_paths[r], file_idx++);
    }

    if (skipped > 0)
        fprintf(stderr, "# CORPUS_MAX_TIME reached: %d files skipped\n",
            skipped);

    if (!mfail_is_installed() || mfail_is_count_only()) {
        fprintf(stderr, "# corpus_files: total=%d selected=%d\n",
            corpus_total, selected);
        fprintf(stderr, "# corpus_time: %.6f\n", secs_since(corpus_start));
    }

    for (n = 0; n < corpus_total; n++)
        free(corpus_paths[n]);
    free(corpus_paths);

    FuzzerCleanup();
    return 0;
}
