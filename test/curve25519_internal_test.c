/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "crypto/ecx.h"
#include "internal/nelem.h"
#include "testutil.h"

/*
 * Decoding of Ed25519 public keys with small y coordinates. Decoding
 * involves subtractions and comparisons of unreduced field elements, so
 * these are regression tests for the base 2^51 field arithmetic: computing
 * vx^2-u instead of u-vx^2 in ge_frombytes_vartime() makes y = 5 fail, and
 * encoding field elements without first propagating carries makes most of
 * the others fail.
 */
static const struct {
    uint8_t y;
    int valid;
} decode_tests[] = {
    { 0, 1 }, /* x found via sqrt(-1) */
    { 1, 1 }, /* the neutral element */
    { 2, 0 },
    { 3, 1 },
    { 4, 1 }, /* x found via sqrt(-1) */
    { 5, 1 },
    { 6, 1 },
    { 7, 0 },
    { 8, 0 },
    { 9, 1 },
    { 10, 1 }, /* x found via sqrt(-1) */
    { 11, 0 },
};

static int test_ed25519_decode(int idx)
{
    uint8_t pub[32] = { 0 };

    pub[0] = decode_tests[idx].y;
    return TEST_int_eq(ossl_ed25519_pubkey_verify(pub, sizeof(pub)),
        decode_tests[idx].valid);
}

/* RFC 8032 section 7.1, test 1 */
static int test_ed25519_decode_rfc8032(void)
{
    static const uint8_t pub[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
        0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };

    return TEST_int_eq(ossl_ed25519_pubkey_verify(pub, sizeof(pub)), 1);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_ed25519_decode, OSSL_NELEM(decode_tests));
    ADD_TEST(test_ed25519_decode_rfc8032);
    return 1;
}
