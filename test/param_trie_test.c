/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * This program tests the use of OSSL_PARAM TRIE.
 */

#include <openssl/core.h>
#include <openssl/params.h>
#include "internal/numbers.h"
#include "crypto/param_trie.h"
#include "internal/nelem.h"
#include "testutil.h"

static const OSSL_PARAM known[] = {
    OSSL_PARAM_int("mmmmm", NULL),      /* 0 */
    OSSL_PARAM_int("a", NULL),          /* 1 */
    OSSL_PARAM_int("z", NULL),          /* 2 */
    OSSL_PARAM_int("mmmmmm2", NULL),    /* 3 */
    OSSL_PARAM_int("mmmmmm", NULL),     /* 4 */
    OSSL_PARAM_int("aa", NULL),         /* 5 */
    OSSL_PARAM_int("zz", NULL),         /* 6 */
    OSSL_PARAM_int("dd", NULL),         /* 7 */
    OSSL_PARAM_int("qq", NULL),         /* 8 */
    OSSL_PARAM_END
};
static OSSL_PARAM passed[] = {
    OSSL_PARAM_int("mmmmm", NULL),      /* 0 */
    OSSL_PARAM_int("a", NULL),          /* 1 */
    OSSL_PARAM_int("z", NULL),          /* 2 */
    OSSL_PARAM_int("dd", NULL),         /* 3 */
    OSSL_PARAM_int("qq", NULL),         /* 4 */
    OSSL_PARAM_int("mmmmmm", NULL),     /* 5 */
    OSSL_PARAM_int("mmmmmm2", NULL),    /* 6 */
    OSSL_PARAM_int("zz", NULL),         /* 7 */
    OSSL_PARAM_int("fnord", NULL),      /* 8 */
    /* OSSL_PARAM_int("aa", NULL) is deliberately missing */
    OSSL_PARAM_END
};

static int test_trie(void)
{
    OSSL_PTRIE *pt;
    int res = 0;

    OSSL_PTRIE_PARAM_IDX idxs[OSSL_NELEM(known) - 1];
    pt = ossl_ptrie_new(known);
#ifndef OPENSSL_SMALL_FOOTPRINT
    if (!TEST_ptr(pt))
        goto err;
#endif
    if (!TEST_true(ossl_ptrie_scan(pt, passed, OSSL_NELEM(idxs), idxs)))
        goto err;

    if (TEST_ptr_eq(ossl_ptrie_locate(0, passed, idxs, "mmmmm"), passed)
            && TEST_ptr_eq(ossl_ptrie_locate(1, passed, idxs, "a"), passed + 1)
            && TEST_ptr_eq(ossl_ptrie_locate(2, passed, idxs, "z"), passed + 2)
            && TEST_ptr_eq(ossl_ptrie_locate(2, passed, NULL, "z"), passed + 2)
            && TEST_ptr_eq(ossl_ptrie_locate(3, passed, idxs, "mmmmmm2"),
                           passed + 6)
            && TEST_ptr_eq(ossl_ptrie_locate(4, passed, idxs, "mmmmmm"),
                           passed + 5)
            && TEST_ptr_null(ossl_ptrie_locate_const(5, passed, idxs, "aa"))
            && TEST_ptr_eq(ossl_ptrie_locate_const(6, passed, idxs, "zz"),
                           passed + 7)
            && TEST_ptr_eq(ossl_ptrie_locate_const(7, passed, idxs, "dd"),
                           passed + 3)
            && TEST_ptr_eq(ossl_ptrie_locate_const(8, passed, idxs, "qq"),
                           passed + 4)
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, idxs, "fnord"),
                                                   passed + 8)
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, NULL, "fnord"),
                                                   passed + 8)
            && TEST_ptr_eq(ossl_ptrie_locate(-1, passed, idxs, "mmmmm"), passed)
            && TEST_ptr_eq(ossl_ptrie_locate(-1, passed, idxs, "a"), passed + 1)
            && TEST_ptr_eq(ossl_ptrie_locate(-1, passed, idxs, "z"), passed + 2)
            && TEST_ptr_eq(ossl_ptrie_locate(-1, passed, idxs, "mmmmmm2"),
                                             passed + 6)
            && TEST_ptr_eq(ossl_ptrie_locate(-1, passed, idxs, "mmmmmm"),
                                             passed + 5)
            && TEST_ptr_null(ossl_ptrie_locate_const(-1, passed, idxs, "aa"))
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, idxs, "zz"),
                                                   passed + 7)
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, idxs, "dd"),
                                                   passed + 3)
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, idxs, "qq"),
                                                   passed + 4)
            && TEST_ptr_eq(ossl_ptrie_locate_const(-1, passed, idxs, "fnord"),
                                                   passed + 8)
            && TEST_ptr_null(ossl_ptrie_locate_const(-1, passed, idxs, "aaa"))
            && TEST_ptr_null(ossl_ptrie_locate_const(-1, passed, idxs, "ab"))
            && TEST_ptr_null(ossl_ptrie_locate_const(-1, passed, idxs, "d"))
            && TEST_ptr_null(ossl_ptrie_locate_const(-1, passed, idxs, "q"))
            && TEST_ptr_null(ossl_ptrie_locate(-1, passed, idxs, "dfg"))
            && TEST_ptr_null(ossl_ptrie_locate(-1, passed, idxs, "qrs"))
            && TEST_ptr_null(ossl_ptrie_locate(-1, passed, idxs, "mmmm")))
        res = 1;
 err:
    ossl_ptrie_free(pt);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(test_trie);
    return 1;
}
