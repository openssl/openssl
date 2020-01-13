/*
 * Copyright 2017-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/* Internal tests for the x509 and x509v3 modules */

#include <stdio.h>
#include <string.h>

#include <opentls/tls.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "../tls/tls_local.h"
#include "../tls/tls_cert_table.h"

#define test_cert_table(nid, amask, idx) \
    do_test_cert_table(nid, amask, idx, #idx)

static int do_test_cert_table(int nid, uint32_t amask, size_t idx,
                              const char *idxname)
{
    const tls_CERT_LOOKUP *clu = &tls_cert_info[idx];

    if (clu->nid == nid && clu->amask == amask)
        return 1;

    TEST_error("Invalid table entry for certificate type %s, index %zu",
               idxname, idx);
    if (clu->nid != nid)
        TEST_note("Expected %s, got %s\n", OBJ_nid2sn(nid),
                  OBJ_nid2sn(clu->nid));
    if (clu->amask != amask)
        TEST_note("Expected auth mask 0x%x, got 0x%x\n", amask, clu->amask);
    return 0;
}

/* Sanity check of tls_cert_table */

static int test_tls_cert_table(void)
{
    TEST_size_t_eq(Otls_NELEM(tls_cert_info), tls_PKEY_NUM);
    if (!test_cert_table(EVP_PKEY_RSA, tls_aRSA, tls_PKEY_RSA))
        return 0;
    if (!test_cert_table(EVP_PKEY_DSA, tls_aDSS, tls_PKEY_DSA_SIGN))
        return 0;
    if (!test_cert_table(EVP_PKEY_EC, tls_aECDSA, tls_PKEY_ECC))
        return 0;
    if (!test_cert_table(NID_id_GostR3410_2001, tls_aGOST01, tls_PKEY_GOST01))
        return 0;
    if (!test_cert_table(NID_id_GostR3410_2012_256, tls_aGOST12,
                         tls_PKEY_GOST12_256))
        return 0;
    if (!test_cert_table(NID_id_GostR3410_2012_512, tls_aGOST12,
                         tls_PKEY_GOST12_512))
        return 0;
    if (!test_cert_table(EVP_PKEY_ED25519, tls_aECDSA, tls_PKEY_ED25519))
        return 0;
    if (!test_cert_table(EVP_PKEY_ED448, tls_aECDSA, tls_PKEY_ED448))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_tls_cert_table);
    return 1;
}
