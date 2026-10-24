/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "internal/nelem.h"
#include "internal/secret_check.h"
#include "testutil.h"

/*
 * Vectors generated and cross-checked by .clown/secret_check_model.py.
 * random* are fixed pseudo-random bytes that pass every test; the rest
 * each isolate one test at its boundary, or reproduce a known mistake.
 */
static const struct {
    const char *name;
    const char *hex;
    size_t width_bits;
    int expected;
} vectors[] = {
    { "random32 as scalar",
        "db7621f5ec883dab4475cfe0a1b398262b92fd66606634877381d6b5c369735c",
        256, 1 },
    { "random32 as seed",
        "db7621f5ec883dab4475cfe0a1b398262b92fd66606634877381d6b5c369735c",
        0, 1 },
    { "random48",
        "ea1437602e98962c9f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51df500a8552a40b6f2",
        384, 1 },
    { "random64 as seed",
        "ddaf0ce5c19b63480a00ef768da6d3a54e0b60ee0a718919e3e4909ac4eba1aa"
        "fc0ec3ef1b39c6a3225d38895ac60e8f016283121760e42236bbc53ee69199b9",
        0, 1 },
    { "random66 P-521 width",
        "0155434d219a8c6c076852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e80d10fb269ba3b82"
        "4bdf",
        521, 1 },
    /* magnitude: 63 leading zero bits pass, 64 fail; zero count below 12 */
    { "magnitude 63 zero bits",
        "00000000000000019f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51df500a8552a40b6f2",
        384, 1 },
    { "magnitude 64 zero bits",
        "00000000000000008099a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51df500a8552a40b6f2",
        384, 0 },
    /* the same boundary read little-endian */
    { "little-endian magnitude 63 zero bits",
        "ea1437602e98962c9f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51d0100000000000000",
        384, 1 },
    { "little-endian magnitude 64 zero bits",
        "ea1437602e98962c9f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b5800000000000000000",
        384, 0 },
    /* P-521: the 7 pad bits of byte 0 are ignored; valid bit 0 is clear */
    { "P-521 pad bits set, 57 valid zero bits",
        "fe00000000000000806852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e80d10fb269ba3b82"
        "4bdf",
        521, 1 },
    { "P-521 pad bits set, 65 valid zero bits",
        "fe00000000000000008052ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e80d10fb269ba3b82"
        "4bdf",
        521, 0 },
    /* P-521 little-endian: the pad bits are the high bits of the last byte */
    { "P-521 little-endian pad bits set, 57 valid zero bits",
        "0155434d219a8c6c076852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e808000000000000000"
        "fe",
        521, 1 },
    { "P-521 little-endian pad bits set, 65 valid zero bits",
        "0155434d219a8c6c076852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e800000000000000000"
        "fe",
        521, 0 },
    /* zero-byte count: 7 of 32 pass, 8 fail */
    { "7 zero bytes",
        "db7621f5ec883dab4400cfe000b398002b920066600034870081d600c369735c",
        256, 1 },
    { "8 zero bytes",
        "db7621f5ec883dab4400cfe000b398002b920066600034870081d600c369005c",
        256, 0 },
    /* distinct byte values: 8 of 32 pass, 7 fail */
    { "8 distinct values",
        "8091a2b3c4d5e6f78091a2b3c4d5e6f78091a2b3c4d5e6f78091a2b3c4d5e6f7",
        256, 1 },
    { "7 distinct values",
        "8091a2b3c4d5e68091a2b3c4d5e68091a2b3c4d5e68091a2b3c4d5e68091a2b3",
        256, 0 },
    /* printable ASCII */
    { "all printable",
        "534c4f54333a4b45593137202020202020202020202020202020202020202020",
        256, 0 },
    { "printable but one byte",
        "534c4f54333a4b4559313720202020202020202020202020202020202020201f",
        256, 1 },
    /* handles mistaken for keys */
    { "big-endian 4",
        "0000000000000000000000000000000000000000000000000000000000000004",
        256, 0 },
    { "little-endian 4",
        "0400000000000000000000000000000000000000000000000000000000000000",
        256, 0 },
    { "little-endian 4 as 64-byte seed",
        "0400000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        0, 0 },
    { "0xaa fill",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        256, 0 },
};

static int test_vector(int idx)
{
    unsigned char *buf = NULL;
    long len = 0;
    int ret = 0;

    TEST_info("%s", vectors[idx].name);
    if (!TEST_ptr(buf = OPENSSL_hexstr2buf(vectors[idx].hex, &len)))
        return 0;
    ret = TEST_int_eq(ossl_secret_bytes_check(buf, (size_t)len,
                          vectors[idx].width_bits),
        vectors[idx].expected);
    OPENSSL_free(buf);
    return ret;
}

/* Below the minimum length nothing is tested, so even all zeros passes */
static int test_short_input(void)
{
    const uint8_t buf[OSSL_SECRET_CHECK_MIN_LEN] = { 0 };

    return TEST_int_eq(ossl_secret_bytes_check(buf, sizeof(buf), 0), 0)
        && TEST_int_eq(ossl_secret_bytes_check(buf, sizeof(buf) - 1, 0), 1);
}

/*
 * A 1024-byte secret can hold at most 256 distinct byte values, so the
 * distinct-value demand must be capped: 200 distinct values pass.
 */
static int test_wide_distinct(void)
{
    uint8_t buf[1024];
    size_t i;

    for (i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)((i * 7) % 200 + 50);
    return TEST_int_eq(ossl_secret_bytes_check(buf, sizeof(buf),
                           sizeof(buf) * 8),
        1);
}

static int test_bn(void)
{
    BIGNUM *bn = NULL;
    int ret = 0;

    if (!TEST_ptr(bn = BN_new()))
        return 0;

    /* the incident: d = 4 */
    if (!TEST_true(BN_set_word(bn, 4))
        || !TEST_int_eq(ossl_secret_bn_check(bn, 256), 0))
        goto err;

    /* d = 1 */
    if (!TEST_true(BN_one(bn))
        || !TEST_int_eq(ossl_secret_bn_check(bn, 256), 0))
        goto err;

    /* a plausible scalar */
    if (!TEST_true(BN_hex2bn(&bn,
            "db7621f5ec883dab4475cfe0a1b398262b92fd66606634877381d6b5c369735c"))
        || !TEST_int_eq(ossl_secret_bn_check(bn, 256), 1))
        goto err;

    /* the same scalar does not fit a 248-bit (31-byte) width */
    if (!TEST_int_eq(ossl_secret_bn_check(bn, 248), 0))
        goto err;

    /* and is rejected at P-521 width, where it has 265 leading zero bits */
    if (!TEST_int_eq(ossl_secret_bn_check(bn, 521), 0))
        goto err;

    ret = 1;
err:
    BN_free(bn);
    return ret;
}

static int test_switch(void)
{
#if defined(OPENSSL_NO_SECRET_CHECK)
    const int initial = 0;
#else
    const int initial = 1;
#endif /* defined(OPENSSL_NO_SECRET_CHECK) */
    int ret = 0;

    if (!TEST_int_eq(ossl_secret_check_enabled(), initial))
        return 0;
    if (!TEST_true(CRYPTO_secret_check_disable())
        || !TEST_int_eq(ossl_secret_check_enabled(), 0)
        || !TEST_true(CRYPTO_secret_check_enable())
        || !TEST_int_eq(ossl_secret_check_enabled(), 1))
        goto err;
    ret = 1;
err:
    /* leave the switch as the build configured it */
    if (initial)
        CRYPTO_secret_check_enable();
    else
        CRYPTO_secret_check_disable();
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_vector, OSSL_NELEM(vectors));
    ADD_TEST(test_short_input);
    ADD_TEST(test_wide_distinct);
    ADD_TEST(test_bn);
    ADD_TEST(test_switch);
    return 1;
}
