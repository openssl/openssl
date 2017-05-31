/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the asn1 module */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "testutil.h"
#include "e_os.h"

/**********************************************************************
 *
 * Test of a_strnid's tbl_standard
 *
 ***/

#include "../crypto/asn1/tbl_standard.h"

static int test_tbl_standard()
{
    const ASN1_STRING_TABLE *tmp;
    int last_nid = -1;
    size_t i;

    for (tmp = tbl_standard, i = 0; i < OSSL_NELEM(tbl_standard); i++, tmp++) {
        if (tmp->nid < last_nid) {
            last_nid = 0;
            break;
        }
        last_nid = tmp->nid;
    }

    if (last_nid != 0) {
        fprintf(stderr, "asn1 tbl_standard: Table order OK\n");
        return 1;
    }

    for (tmp = tbl_standard, i = 0; i < OSSL_NELEM(tbl_standard); i++, tmp++)
        fprintf(stderr, "asn1 tbl_standard: Index %" OSSLzu ", NID %d, Name=%s\n",
                i, tmp->nid, OBJ_nid2ln(tmp->nid));

    return 0;
}

/**********************************************************************
 *
 * Test of ameth_lib's standard_methods
 *
 ***/

#include "internal/asn1_int.h"
#include "../crypto/asn1/standard_methods.h"

static int test_standard_methods()
{
    const EVP_PKEY_ASN1_METHOD **tmp;
    int last_pkey_id = -1;
    size_t i;

    for (tmp = standard_methods, i = 0; i < OSSL_NELEM(standard_methods);
         i++, tmp++) {
        if ((*tmp)->pkey_id < last_pkey_id) {
            last_pkey_id = 0;
            break;
        }
        last_pkey_id = (*tmp)->pkey_id;
    }

    if (last_pkey_id != 0) {
        fprintf(stderr, "asn1 standard methods: Table order OK\n");
        return 1;
    }

    TEST_error("asn1 standard methods out of order");
    for (tmp = standard_methods, i = 0; i < OSSL_NELEM(standard_methods);
         i++, tmp++)
        fprintf(stderr, "asn1 standard methods: Index %" OSSLzu
                ", pkey ID %d, Name=%s\n", i, (*tmp)->pkey_id,
                OBJ_nid2sn((*tmp)->pkey_id));

    return 0;
}

void register_tests(void)
{
    ADD_TEST(test_tbl_standard);
    ADD_TEST(test_standard_methods);
}
