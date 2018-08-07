/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 BaishanCloud. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for ZUC keystream generation.
 *
 * All tests come from 3GPP specification - Specification of the 3GPP
 * Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3 Document 3:
 * Implementor’s Test Data
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"

#ifndef OPENSSL_NO_ZUC
# include "internal/zuc.h"

typedef struct zuc_test_st {
    uint8_t key[16];
    uint8_t iv[16];
    uint32_t L;
    uint32_t output[3]; /* store the 2000th output in output[2] */
} ZUC_TV;

static ZUC_TV ztv[4] = {

    /* Test 1 */
    {
        /* Key */
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },

        /* IV */
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },

        /* L */
        2,

        /* output */
        { 0x27bede74, 0x018082da, 0x0 }
    },

    /* Test 2 */
    {
        /* Key */
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        },

        /* IV */
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        },

        /* L */
        2,

        /* output */
        { 0x0657cfa0, 0x7096398b, 0x0 }
    },

    /* Test 3 */
    {
        /* Key */
        {
            0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae,
            0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b
        },

        /* IV */
        {
            0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca,
            0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66
        },

        /* L */
        2,

        /* output */
        { 0x14f1c272, 0x3279c419, 0x0 }
    },

    /* Test 4 */
    {
        /* Key */
        {
            0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf,
            0xd6, 0xb8, 0xbd, 0x00, 0xf3, 0x9d, 0x8b, 0x41
        },

        /* IV */
        {
            0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e,
            0xce, 0x2d, 0xc3, 0x15, 0x04, 0x9e, 0xb5, 0x74
        },

        /* L */
        2000,

        /* output */
        { 0xed4400e7, 0x0633e5c5, 0x7a574cdb }
    }
};

static int test_zuc(int idx)
{
    ZUC_KEY zk;
    int ret, i;
    uint32_t z;

    /* setup */
    memset(&zk, 0, sizeof(ZUC_KEY));
    zk.k = ztv[idx].key;
    memcpy(zk.iv, ztv[idx].iv, 16);
    zk.L = ztv[idx].L;

    ZUC_init(&zk);

    ret = ZUC_generate_keystream(&zk);
    if (!ret) {
        TEST_error("Fail to generate ZUC keystrean (round %d)", idx);
        return 0;
    }

    for (i = 0; i < 3; i++) {
        if (ztv[idx].output[i] != 0) {
            /*
             * in the spec, one test reads the last keystream byte
             */
            if (i == 2)
                z = zk.keystream[7996] << 24 | zk.keystream[7997] << 16
                    | zk.keystream[7998] << 8 | zk.keystream[7999];
            else
                z = zk.keystream[i * 4] << 24 | zk.keystream[i * 4 + 1] << 16
                    | zk.keystream[i * 4 + 2] << 8 | zk.keystream[i * 4 + 3];

            if (!TEST_uint_eq(z, ztv[idx].output[i])) {
                TEST_info("Current compared key: %d", i);
                return 0;
            }
        }
    }

    ZUC_destroy_keystream(&zk);

    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ZUC
    ADD_ALL_TESTS(test_zuc, 4);
#endif
    return 1;
}
