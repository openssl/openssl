/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>

#include "internal/xxhash.h"
#include "internal/nelem.h"
#include "testutil.h"

static int test_xxh3_seed_zero_length(void)
{
    static const struct {
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 0, 0x2D06800538D394C2ULL },
        { 0x9E3779B185EBCA8DULL, 0xA8A6B918B2F0364AULL },
    };
    uint64_t hash = 0;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        if (!TEST_true(hash = ossl_xxh3(NULL, 0, tests[i].seed))
            || !TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_len_1to3(void)
{
    static const unsigned char input[] = { 0x00, 0x52, 0x92 };
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 1, 0, 0xC44BDFF4074EECDBULL },
        { 1, 0x9E3779B185EBCA8DULL, 0x032BE332DD766EF8ULL },
        { 2, 0, 0x7A9978044CB8A8BBULL },
        { 2, 0x9E3779B185EBCA8DULL, 0x764B35C90519AD88ULL },
        { 3, 0, 0x54247382A8D6B94DULL },
        { 3, 0x9E3779B185EBCA8DULL, 0x634B8990B4976373ULL },
    };
    uint64_t hash;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_len_4to8(void)
{
    static const unsigned char input[] = {
        0x00, 0x52, 0x92, 0x9b, 0xb7, 0x32, 0xa3, 0x24
    };
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 4, 0, 0xE5DC74BC51848A51ULL },
        { 4, 0x9E3779B185EBCA8DULL, 0xAA2E7ECCB0C8F747ULL },
        { 5, 0, 0xE4243F00720306BBULL },
        { 5, 0x9E3779B185EBCA8DULL, 0x5A67C87E50ED80EDULL },
        { 6, 0, 0x27B56A84CD2D7325ULL },
        { 6, 0x9E3779B185EBCA8DULL, 0x84589C116AB59AB9ULL },
        { 7, 0, 0x9941E0007F555E50ULL },
        { 7, 0x9E3779B185EBCA8DULL, 0x75BDAB43463F0151ULL },
        { 8, 0, 0x24CCC9ACAA9F65E4ULL },
        { 8, 0x9E3779B185EBCA8DULL, 0x8F973410999B8F6BULL },
    };
    uint64_t hash;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_len_9to16(void)
{
    static const unsigned char input[] = {
        0x00, 0x52, 0x92, 0x9b, 0xb7, 0x32, 0xa3, 0x24,
        0x2d, 0x00, 0xaf, 0x95, 0x0e, 0xec, 0xb8, 0x93
    };
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 9, 0, 0x14D5001C15DD3F2BULL },
        { 9, 0x9E3779B185EBCA8DULL, 0xB3AE7333D9013F60ULL },
        { 10, 0, 0x1C117F233FBC3C14ULL },
        { 10, 0x9E3779B185EBCA8DULL, 0x5B8A62DB39366886ULL },
        { 11, 0, 0x889839B4C796DDD6ULL },
        { 11, 0x9E3779B185EBCA8DULL, 0x72D41CE6ECFFAA96ULL },
        { 12, 0, 0xA713DAF0DFBB77E7ULL },
        { 12, 0x9E3779B185EBCA8DULL, 0xE7303E1B2336DE0EULL },
        { 13, 0, 0x2EB03C6E66BA6524ULL },
        { 13, 0x9E3779B185EBCA8DULL, 0x0D7ECCE7A8C882EFULL },
        { 14, 0, 0x1AC0BBDA2B9FCF03ULL },
        { 14, 0x9E3779B185EBCA8DULL, 0xA7F68521581B173FULL },
        { 15, 0, 0x45556D4D6E1798BCULL },
        { 15, 0x9E3779B185EBCA8DULL, 0x710DD5318F6F16D5ULL },
        { 16, 0, 0x981B17D36C7498C9ULL },
        { 16, 0x9E3779B185EBCA8DULL, 0x663F29333B4DB6B1ULL },
    };
    uint64_t hash;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_len_17to128(void)
{
    static const unsigned char input[] = {
        0x00, 0x52, 0x92, 0x9b, 0xb7, 0x32, 0xa3, 0x24,
        0x2d, 0x00, 0xaf, 0x95, 0x0e, 0xec, 0xb8, 0x93,
        0xe3, 0xdf, 0xef, 0x93, 0xaa, 0xd6, 0xcd, 0x2a,
        0x53, 0x8b, 0x5c, 0x3f, 0x54, 0x5a, 0x6f, 0xd5,
        0x59, 0xc0, 0xff, 0xfc, 0x8f, 0x85, 0xb9, 0x33,
        0x1d, 0xab, 0x74, 0xf7, 0xb6, 0x05, 0x93, 0x27,
        0xb0, 0x70, 0x84, 0xb3, 0x67, 0x7c, 0x9f, 0x76,
        0x48, 0x00, 0x72, 0xed, 0x7b, 0x98, 0x17, 0xe8,
        0xdd, 0x48, 0x5e, 0x0c, 0x0c, 0xcb, 0xd0, 0x65,
        0x3f, 0xad, 0xb2, 0x8f, 0x11, 0xb0, 0x6c, 0xe8,
        0x8d, 0xb0, 0xf1, 0x86, 0x08, 0x61, 0x59, 0x56,
        0x6c, 0x8e, 0x4e, 0x78, 0x13, 0x63, 0xbd, 0xab,
        0x9d, 0x32, 0x73, 0x09, 0xea, 0x71, 0x2f, 0xd9,
        0x7a, 0x9d, 0x55, 0xf0, 0xca, 0x8a, 0xd0, 0xe9,
        0x5e, 0x1a, 0x36, 0xb3, 0x6b, 0x0f, 0xca, 0x51,
        0xef, 0x8b, 0xa2, 0xc4, 0x62, 0xed, 0x00, 0x96
    };
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 17, 0, 0x796F5ACD3A60F862ULL },
        { 17, 0x9E3779B185EBCA8DULL, 0xF3EC5067F4306DB3ULL },
        { 32, 0, 0x9FEADDBDBF57EED3ULL },
        { 32, 0x9E3779B185EBCA8DULL, 0x2199FAB1534893D9ULL },
        { 33, 0, 0xABFB2D081B400A10ULL },
        { 33, 0x9E3779B185EBCA8DULL, 0xAD56348DA574BB6DULL },
        { 64, 0, 0x9CB48487720EC49DULL },
        { 64, 0x9E3779B185EBCA8DULL, 0x4FE8895DB9B8C077ULL },
        { 65, 0, 0xFD81AAC4BEBC3883ULL },
        { 65, 0x9E3779B185EBCA8DULL, 0xAD80AEEC1FC9E0A7ULL },
        { 96, 0, 0x935A769A7F94776FULL },
        { 96, 0x9E3779B185EBCA8DULL, 0x70CF51937E500540ULL },
        { 97, 0, 0xCA4CA268FD3C3A6CULL },
        { 97, 0x9E3779B185EBCA8DULL, 0xEE461D3ADD7EE6C9ULL },
        { 128, 0, 0xFCFF24126754D861ULL },
        { 128, 0x9E3779B185EBCA8DULL, 0x73FDE75280646649ULL },
    };
    uint64_t hash;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_len_129to240(void)
{
    static const unsigned char input[] = {
        0x00, 0x52, 0x92, 0x9b, 0xb7, 0x32, 0xa3, 0x24,
        0x2d, 0x00, 0xaf, 0x95, 0x0e, 0xec, 0xb8, 0x93,
        0xe3, 0xdf, 0xef, 0x93, 0xaa, 0xd6, 0xcd, 0x2a,
        0x53, 0x8b, 0x5c, 0x3f, 0x54, 0x5a, 0x6f, 0xd5,
        0x59, 0xc0, 0xff, 0xfc, 0x8f, 0x85, 0xb9, 0x33,
        0x1d, 0xab, 0x74, 0xf7, 0xb6, 0x05, 0x93, 0x27,
        0xb0, 0x70, 0x84, 0xb3, 0x67, 0x7c, 0x9f, 0x76,
        0x48, 0x00, 0x72, 0xed, 0x7b, 0x98, 0x17, 0xe8,
        0xdd, 0x48, 0x5e, 0x0c, 0x0c, 0xcb, 0xd0, 0x65,
        0x3f, 0xad, 0xb2, 0x8f, 0x11, 0xb0, 0x6c, 0xe8,
        0x8d, 0xb0, 0xf1, 0x86, 0x08, 0x61, 0x59, 0x56,
        0x6c, 0x8e, 0x4e, 0x78, 0x13, 0x63, 0xbd, 0xab,
        0x9d, 0x32, 0x73, 0x09, 0xea, 0x71, 0x2f, 0xd9,
        0x7a, 0x9d, 0x55, 0xf0, 0xca, 0x8a, 0xd0, 0xe9,
        0x5e, 0x1a, 0x36, 0xb3, 0x6b, 0x0f, 0xca, 0x51,
        0xef, 0x8b, 0xa2, 0xc4, 0x62, 0xed, 0x00, 0x96,
        0xf3, 0x34, 0x49, 0xeb, 0x0f, 0xd1, 0x3b, 0x92,
        0xa1, 0xa9, 0x63, 0xdb, 0xaa, 0xed, 0x3d, 0xcf,
        0xf1, 0x09, 0x42, 0xcd, 0xf9, 0xb3, 0x21, 0xa2,
        0xeb, 0xf2, 0xc8, 0xf4, 0xe4, 0x2f, 0x48, 0xd1,
        0x4b, 0x10, 0xf4, 0xc2, 0xef, 0xec, 0xf8, 0x4a,
        0xb5, 0x38, 0x74, 0xc3, 0xa4, 0xa6, 0x62, 0x0e,
        0xbf, 0xfd, 0x63, 0x37, 0x41, 0xe3, 0x86, 0x98,
        0x1a, 0xeb, 0x4c, 0xba, 0x56, 0x03, 0x66, 0x87,
        0xed, 0x00, 0x45, 0x59, 0xc1, 0x85, 0x44, 0xb6,
        0xc3, 0x68, 0xf9, 0x41, 0xa9, 0xea, 0xf9, 0x87,
        0xe0, 0x9f, 0x12, 0xd0, 0xd5, 0x14, 0x54, 0x48,
        0x5d, 0x44, 0x40, 0x51, 0xe3, 0x38, 0x06, 0x9a,
        0x4c, 0x3c, 0x0d, 0xef, 0x64, 0x89, 0xf8, 0xa3,
        0x61, 0xee, 0xe3, 0xc5, 0x1c, 0x93, 0x68, 0xc8
    };
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 129, 0, 0x98F1B0A679A2CA29ULL },
        { 129, 0x9E3779B185EBCA8DULL, 0x21FFFDBCA099C844ULL },
        { 143, 0, 0x7A7813693F1F4EDBULL },
        { 143, 0x9E3779B185EBCA8DULL, 0x43B3274AE68D5742ULL },
        { 144, 0, 0xC440D47E5F03FE58ULL },
        { 144, 0x9E3779B185EBCA8DULL, 0x858D16B71F4DD859ULL },
        { 159, 0, 0x7CB32A6ECDEBAF1CULL },
        { 159, 0x9E3779B185EBCA8DULL, 0xACFF1F7B6CC1FDC9ULL },
        { 160, 0, 0x9D03A319ED4CBD2BULL },
        { 160, 0x9E3779B185EBCA8DULL, 0x3825C75FFE70FDE0ULL },
        { 175, 0, 0xA414B77DF2FDABAEULL },
        { 175, 0x9E3779B185EBCA8DULL, 0x8F19B0614DB0B814ULL },
        { 176, 0, 0x6A79C99804538253ULL },
        { 176, 0x9E3779B185EBCA8DULL, 0x25B3750065BA47EFULL },
        { 191, 0, 0x759FFC8FF8FB94BDULL },
        { 191, 0x9E3779B185EBCA8DULL, 0xABCD155AD6E9F3B6ULL },
        { 192, 0, 0xAF9F58E78B8D3587ULL },
        { 192, 0x9E3779B185EBCA8DULL, 0x69E006AA2156C999ULL },
        { 207, 0, 0x56FFE054ABC6F401ULL },
        { 207, 0x9E3779B185EBCA8DULL, 0x056F05B3D4F7BCEFULL },
        { 208, 0, 0x2CF1E5EB7433AA4DULL },
        { 208, 0x9E3779B185EBCA8DULL, 0xA351C8376638C444ULL },
        { 223, 0, 0x6E495316B983036EULL },
        { 223, 0x9E3779B185EBCA8DULL, 0x9F9CEFACCFEE917DULL },
        { 224, 0, 0x3F3250C7E92C871AULL },
        { 224, 0x9E3779B185EBCA8DULL, 0x17023A9A6F1156DBULL },
        { 239, 0, 0x16CE2B9D3B28805DULL },
        { 239, 0x9E3779B185EBCA8DULL, 0xF59F5C23FCEBD3B7ULL },
        { 240, 0, 0x81C3C2B67F568CCFULL },
        { 240, 0x9E3779B185EBCA8DULL, 0xCC0F58C27EF3D8EEULL },
    };
    uint64_t hash;
    size_t i;

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

static int test_xxh3_seed_hash_long(void)
{
    unsigned char input[4160];
    static const struct {
        size_t len;
        uint64_t seed;
        uint64_t expected;
    } tests[] = {
        { 241, 0, 0xC5A639ECD2030E5EULL },
        { 241, 0x9E3779B185EBCA8DULL, 0xDDA9B0A161D4829AULL },
        { 256, 0, 0x55DE574AD89D0AC5ULL },
        { 256, 0x9E3779B185EBCA8DULL, 0x4D30234B7A3AA61CULL },
        { 512, 0, 0x617E49599013CB6BULL },
        { 512, 0x9E3779B185EBCA8DULL, 0x3CE457DE14C27708ULL },
        { 1024, 0, 0xDD85C9B5C1109C5CULL },
        { 1024, 0x9E3779B185EBCA8DULL, 0xEF368A8A2EBABAEFULL },
        { 1025, 0, 0xD870C0FA13211C6AULL },
        { 1025, 0x9E3779B185EBCA8DULL, 0x96792BCF9AF88519ULL },
        { 2048, 0, 0xDD59E2C3A5F038E0ULL },
        { 2048, 0x9E3779B185EBCA8DULL, 0x66F81670669ABABCULL },
        { 4096, 0, 0xE91206429D1F48F9ULL },
        { 4096, 0x9E3779B185EBCA8DULL, 0x2A3BBB20A5439DCDULL },
        { 4160, 0, 0x4F323B15321E94E1ULL },
        { 4160, 0x9E3779B185EBCA8DULL, 0x1BF6F5FAF9EECABDULL },
    };
    uint64_t byte_gen = 2654435761U;
    uint64_t hash;
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (unsigned char)(byte_gen >> 56);
        byte_gen *= 11400714785074694797ULL;
    }

    for (i = 0; i < OSSL_NELEM(tests); i++) {
        hash = ossl_xxh3(input, tests[i].len, tests[i].seed);
        if (!TEST_uint64_t_eq(hash, tests[i].expected))
            return 0;
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_xxh3_seed_zero_length);
    ADD_TEST(test_xxh3_seed_len_1to3);
    ADD_TEST(test_xxh3_seed_len_4to8);
    ADD_TEST(test_xxh3_seed_len_9to16);
    ADD_TEST(test_xxh3_seed_len_17to128);
    ADD_TEST(test_xxh3_seed_len_129to240);
    ADD_TEST(test_xxh3_seed_hash_long);

    return 1;
}
