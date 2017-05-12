/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "testutil.h"

/*
 * Password based encryption (PBE) table ordering test.
 * Attempt to look up all supported algorithms.
 */

static int test_pbelu(void)
{
    int i, failed = 0, ok;
    int pbe_type, pbe_nid, last_type = -1, last_nid = -1;

    for (i = 0; EVP_PBE_get(&pbe_type, &pbe_nid, i) != 0; i++) {
        if (!TEST_true(EVP_PBE_find(pbe_type, pbe_nid, NULL, NULL, 0))) {
            TEST_info("i=%d, pbe_type=%d, pbe_nid=%d", i, pbe_type, pbe_nid);
            failed = 1;
            break;
        }
    }

    if (!failed)
        return 1;

    /* Error: print out whole table */
    for (i = 0; EVP_PBE_get(&pbe_type, &pbe_nid, i) != 0; i++) {
        if (pbe_type > last_type)
            ok = 0;
        else if (pbe_type < last_type || pbe_nid < last_nid)
            ok = 1;
        else
            ok = 0;
        if (!ok)
            failed = 1;
        TEST_info("PBE type=%d %d (%s): %s\n", pbe_type, pbe_nid,
                OBJ_nid2sn(pbe_nid), ok ? "ERROR" : "OK");
        last_type = pbe_type;
        last_nid = pbe_nid;
    }
    return failed ? 0 : 1;
}

void register_tests(void)
{
    ADD_TEST(test_pbelu);
}
