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
 * random* are fixed pseudo-random bytes that pass every test; the rest
 * each sit at one test's boundary or are a value mistaken for a key.
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
    /* magnitude: 71 leading zero bits pass, 72 fail */
    { "magnitude 71 zero bits",
        "00000000000000000199a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51df500a8552a40b6f2",
        384, 1 },
    { "magnitude 72 zero bits",
        "00000000000000000080a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b51df500a8552a40b6f2",
        384, 0 },
    /* the same boundary read little-endian */
    { "little-endian magnitude 71 zero bits",
        "ea1437602e98962c9f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a00756b5010000000000000000",
        384, 1 },
    { "little-endian magnitude 72 zero bits",
        "ea1437602e98962c9f99a2af733604749fa6dcf40a0247b13f0198eab5940b9c"
        "d8f659a0075680000000000000000000",
        384, 0 },
    /* P-521: the 7 pad bits of byte 0 are ignored; valid bit 0 is clear */
    { "P-521 pad bits set, 71 valid zero bits",
        "fe00000000000000000252ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e80d10fb269ba3b82"
        "4bdf",
        521, 1 },
    { "P-521 pad bits set, 72 valid zero bits",
        "fe00000000000000000152ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e80d10fb269ba3b82"
        "4bdf",
        521, 0 },
    /* P-521 little-endian: the pad bits are the high bits of the last byte */
    { "P-521 little-endian pad bits set, 71 valid zero bits",
        "0155434d219a8c6c076852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e0200000000000000"
        "00fe",
        521, 1 },
    { "P-521 little-endian pad bits set, 72 valid zero bits",
        "0155434d219a8c6c076852ddcb29661b3eb090e5df8c1a8283155fece16f1f11"
        "9605759485f6f5aca5d5b061c2931674b945f421c32b615e0100000000000000"
        "00fe",
        521, 0 },
    /* a seed is tested over all of its bits */
    { "seed 71 leading zero bits",
        "00000000000000000175cfe0a1b398262b92fd66606634877381d6b5c369735c",
        0, 1 },
    { "seed 72 leading zero bits",
        "00000000000000000080cfe0a1b398262b92fd66606634877381d6b5c369735c",
        0, 0 },
    { "20-byte value right-aligned in a 32-byte seed",
        "000000000000000000000000fb0131ff83be33bac9faac373ac491bef7d3dfc4",
        0, 0 },
    /* zero-byte count: 15 of 32 pass, 16 fail */
    { "15 zero bytes of 32",
        "db002100ec003d004400cf00a10098002b00fd00600034007300d600c300735c",
        256, 1 },
    { "16 zero bytes of 32",
        "db002100ec003d004400cf00a10098002b00fd00600034007300d600c300005c",
        256, 0 },
    /* zero-byte count where len / 4 exceeds 16: 23 of 96 pass, 24 fail */
    { "23 zero bytes of 96",
        "09f400c5d9fb00471c2e00eef40a009e099900b8a05900cae2160079150700ec"
        "7d140049aebd002b2f8e009d1cae0047d48c00524de800dbcffd00a669c80062"
        "02ef00b634ba0063401100ab5bc700913a22004fb28200aa9f04008036d0561e",
        0, 1 },
    { "24 zero bytes of 96",
        "09f400c5d9fb00471c2e00eef40a009e099900b8a05900cae2160079150700ec"
        "7d140049aebd002b2f8e009d1cae0047d48c00524de800dbcffd00a669c80062"
        "02ef00b634ba0063401100ab5bc700913a22004fb28200aa9f04008036d0001e",
        0, 0 },
    /* distinct byte values: 8 of 32 pass, 7 fail */
    { "8 distinct values, no period of 4, 8 or 16",
        "80b3e691c4f7a2d591c4f7a2d580b3e6a2d580b3e691c4f7b3e691c4f7a2d580",
        256, 1 },
    { "7 distinct values",
        "8091a2b3c4d5e68091a2b3c4d5e68091a2b3c4d5e68091a2b3c4d5e68091a2b3",
        256, 0 },
    /* text: 8 NUL bytes of padding pass, 9 fail */
    { "space-padded string",
        "534c4f54333a4b45593137202020202020202020202020202020202020202020",
        256, 1 },
    { "C string with 8 NUL bytes of padding",
        "48534d20736c6f742033206b65792031372068616e646c650000000000000000",
        256, 1 },
    { "C string with 9 NUL bytes of padding",
        "48534d20736c6f742033206b65792031372068616e646c000000000000000000",
        256, 0 },
    /* repetition: a 64-bit handle stamped to fill the field */
    { "8-byte unit four times, exactly 8 distinct values",
        "3a9f1c62d47b08e53a9f1c62d47b08e53a9f1c62d47b08e53a9f1c62d47b08e5",
        256, 0 },
    { "8-byte unit seven times in a 56-byte seed",
        "3a9f1c62d47b08e53a9f1c62d47b08e53a9f1c62d47b08e53a9f1c62d47b08e5"
        "3a9f1c62d47b08e53a9f1c62d47b08e53a9f1c62d47b08e5",
        0, 0 },
    { "12-byte unit repeated",
        "9b2ce7a1d3f582c6b4e09d7f9b2ce7a1d3f582c6b4e09d7f9b2ce7a1d3f582c6",
        256, 1 },
    /* period 8 is tested only with at least 9 bytes compared */
    { "8-byte unit twice, 8 bytes compared",
        "3a9f1c62d47b08e53a9f1c62d47b08e5",
        0, 1 },
    { "8-byte unit twice and one byte, 9 bytes compared",
        "3a9f1c62d47b08e53a9f1c62d47b08e53a",
        0, 0 },
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

/*
 * No test applies to 7 bytes, so all zeros passes there; at 8 bytes the
 * distinct-value test rejects it. The zero-byte demand is floored at 16,
 * so a 16-byte value with 8 zero bytes and no run of 9 at either end
 * passes.
 */
static int test_short_input(void)
{
    const uint8_t zeros[8] = { 0 };
    uint8_t buf[16] = { 0x9c, 0x3e, 0xd1, 0x47, 0xa8, 0x6b, 0xf2, 0x15,
        0xe4, 0x0a, 0xb7, 0x59, 0xc3, 0x8d, 0x26, 0x7f };
    size_t i;

    if (!TEST_int_eq(ossl_secret_bytes_check(zeros, 8, 0), 0)
        || !TEST_int_eq(ossl_secret_bytes_check(zeros, 7, 0), 1)
        || !TEST_int_eq(ossl_secret_bytes_check(buf, sizeof(buf), 128), 1))
        return 0;
    for (i = 0; i < 8; i++)
        buf[2 * i + 1] = 0;
    return TEST_int_eq(ossl_secret_bytes_check(buf, sizeof(buf), 128), 1);
}

/*
 * The distinct-value demand is capped at 64: a 1024-byte value with 200
 * distinct byte values passes.
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

    /* d = 4 */
    if (!TEST_true(BN_set_word(bn, 4))
        || !TEST_int_eq(ossl_secret_bn_check(bn, 256), 0))
        goto err;

    /* d = 1 */
    if (!TEST_true(BN_one(bn))
        || !TEST_int_eq(ossl_secret_bn_check(bn, 256), 0))
        goto err;

    /* a random 256-bit scalar */
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
