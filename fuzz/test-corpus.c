/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include <sys/stat.h>
#include <openssl/crypto.h>
#include "fuzzer.h"
#include "internal/o_dir.h"

#ifdef ERROR_INJECT
# ifdef __linux__
#  include <sys/time.h>
# endif
# ifdef __SANITIZE_ADDRESS__
#  include <sanitizer/asan_interface.h>
# endif

static uint64_t my_seed = 88172645463325252LL;

static void my_srand(uint32_t seed)
{
    uint64_t y = seed;
    y ^= (~y) << 32;
    my_seed = y;
}

static uint32_t my_rand(void)
{
    /*
     * Implement the 64 bit xorshift as suggested by George Marsaglia in:
     *      https://doi.org/10.18637/jss.v008.i14
     */
    uint64_t y = my_seed;
    y ^= y << 13;
    y ^= y >> 7;
    y ^= y << 17;
    my_seed = y;
    return y;
}

static void my_init(void)
{
    static int init = 0;
    if(!init) {
        uint32_t seed;
        char *env = getenv("ERROR_INJECT");
        if (env && *env) {
            seed = atoi(env);
        } else {
# ifdef __linux__
            struct timeval tv;
            gettimeofday(&tv, NULL);
            seed = (uint32_t)(tv.tv_sec ^ tv.tv_usec);
# else
            seed = (uint32_t)time(NULL);
# endif
        }
        my_srand(seed);
        init = 1;
        if (env && !*env) {
# ifdef __SANITIZE_ADDRESS__
            char msg[40];
            sprintf(msg, "ERROR_INJECT=%u", seed);
            __sanitizer_report_error_summary(msg);
# else
            fprintf(stderr, "ERROR_INJECT=%u\n", seed);
            fflush(stderr);
# endif
        }
    }
}

# ifdef ERROR_CALLSTACK
#  ifdef __SANITIZE_ADDRESS__
#   define MY_NULL (__sanitizer_print_stack_trace(),NULL)
#  else
void break_here(void);
void break_here(void)
{
}
#   define MY_NULL (break_here(),NULL)
#  endif
# else
#  define MY_NULL NULL
# endif

static void* my_malloc(size_t s
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    , const char *file
    , int line
#endif
    )
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    (void)file;
    (void)line;
#endif
    my_init();
    return my_rand() % 10000 ? malloc(s) : MY_NULL;
}

static void* my_realloc(void *p, size_t s
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    , const char *file
    , int line
#endif
    )
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    (void)file;
    (void)line;
#endif
    my_init();
    return my_rand() % 100 ? realloc(p, s) : MY_NULL;
}

static void my_free(void *p
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    , const char *file
    , int line
#endif
    )
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    (void)file;
    (void)line;
#endif
    free(p);
}
#endif /* ERROR_INJECT */

#if defined(_WIN32) && defined(_MAX_PATH) && !defined(PATH_MAX)
# define PATH_MAX _MAX_PATH
#endif

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

# if !defined(S_ISREG)
#   define S_ISREG(m) ((m) & S_IFREG)
# endif

static void testfile(const char *pathname)
{
    struct stat st;
    FILE *f;
    unsigned char *buf;
    size_t s;

    if (stat(pathname, &st) < 0 || !S_ISREG(st.st_mode))
        return;
    printf("# %s\n", pathname);
    fflush(stdout);
    f = fopen(pathname, "rb");
    if (f == NULL)
        return;
    buf = malloc(st.st_size);
    if (buf != NULL) {
        s = fread(buf, 1, st.st_size, f);
        OPENSSL_assert(s == (size_t)st.st_size);
#ifdef ERROR_INJECT
        if (s > 0)
            while (my_rand() % 3 <= 1)
                buf[my_rand() % s] = (unsigned char)my_rand();
#endif
        FuzzerTestOneInput(buf, s);
        free(buf);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    int n;

#ifdef ERROR_INJECT
    CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free);
#endif
    FuzzerInitialize(&argc, &argv);

    for (n = 1; n < argc; ++n) {
        size_t dirname_len = strlen(argv[n]);
        const char *filename = NULL;
        char *pathname = NULL;
        OPENSSL_DIR_CTX *ctx = NULL;
        int wasdir = 0;

        /*
         * We start with trying to read the given path as a directory.
         */
        while ((filename = OPENSSL_DIR_read(&ctx, argv[n])) != NULL) {
            wasdir = 1;
            if (pathname == NULL) {
                pathname = malloc(PATH_MAX);
                if (pathname == NULL)
                    break;
                strcpy(pathname, argv[n]);
#ifdef __VMS
                if (strchr(":<]", pathname[dirname_len - 1]) == NULL)
#endif
                    pathname[dirname_len++] = '/';
                pathname[dirname_len] = '\0';
            }
            strcpy(pathname + dirname_len, filename);
            testfile(pathname);
        }
        OPENSSL_DIR_end(&ctx);

        /* If it wasn't a directory, treat it as a file instead */
        if (!wasdir)
            testfile(argv[n]);

        free(pathname);
    }

    FuzzerCleanup();

    return 0;
}
