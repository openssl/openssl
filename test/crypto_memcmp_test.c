/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Functional and constant-time tests for CRYPTO_memcmp().
 *
 * CRYPTO_memcmp() must compare its two operands without any control-flow
 * branch or memory access that depends on the operand *contents* (only the
 * length is public).
 *
 * When built with enable-ct-validation (OPENSSL_CONSTANT_TIME_VALIDATION),
 * CONSTTIME_SECRET marks the operands as "undefined" for Valgrind's memcheck;
 * any branch or memory index derived from them then makes Valgrind exit
 * non-zero. Because the taint is injected here at the call site, this test
 * verifies whichever CRYPTO_memcmp implementation is actually linked -- the
 * per-arch assembler version where one exists (x86_64, aarch64, ...), or the
 * C fallback in crypto/cpuid.c otherwise. Outside a CT build the macros are
 * no-ops and this is an ordinary functional test.
 *
 * The accumulated comparison result is the function's intended *public*
 * output, so it is declassified before being asserted on; the operand buffers
 * are declassified too so the (stack) memory does not stay tainted.
 */

#include <openssl/crypto.h>

#include "internal/nelem.h"
#include "internal/constant_time.h"
#include "testutil.h"

#define MAX_LEN 64

/*
 * len == 16 exercises the dedicated fast path in several assembler versions
 * (e.g. crypto/x86_64cpuid.pl); the other lengths exercise the byte loop and
 * the empty-input early return.
 */
static const struct {
    /* byte length of buffers to compare; must be <= MAX_LEN */
    size_t len;
    /* index at which the second buffer differs, or -1 for equal buffers */
    int diff_pos;
} memcmp_cases[] = {
    /* empty: always equal */
    { 0, -1 },
    { 1, -1 },
    { 1, 0 },

    /* asm fast path (length = 16) */
    { 16, -1 },
    { 16, 0 },
    { 16, 8 },
    { 16, 15 },

    /* byte loop */
    { 64, -1 },
    { 64, 0 },
    { 64, 31 },
    { 64, 63 },
};

static int test_crypto_memcmp(int idx)
{
    size_t i;
    size_t len = memcmp_cases[idx].len;
    int diff_pos = memcmp_cases[idx].diff_pos;
    /* nonzero result iff buffers differ */
    int expected = diff_pos >= 0;
    unsigned char a[MAX_LEN], b[MAX_LEN];
    int result;

    for (i = 0; i < len; i++)
        a[i] = b[i] = (unsigned char)(i * 7 + 1);
    if (diff_pos >= 0)
        b[diff_pos] ^= 0xff;

    CONSTTIME_SECRET(a, len);
    CONSTTIME_SECRET(b, len);

    result = CRYPTO_memcmp(a, b, len);

    CONSTTIME_DECLASSIFY(&result, sizeof(result));
    CONSTTIME_DECLASSIFY(a, len);
    CONSTTIME_DECLASSIFY(b, len);

    if (!TEST_int_eq(result != 0, expected))
        return 0;
    else
        return 1;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_crypto_memcmp, OSSL_NELEM(memcmp_cases));
    return 1;
}
