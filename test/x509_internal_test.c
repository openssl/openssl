/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the x509 and x509v3 modules */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "testutil.h"
#include "test_main.h"
#include "e_os.h"

/**********************************************************************
 *
 * Test of x509v3
 *
 ***/

#include "../crypto/x509v3/ext_dat.h"
#include "../crypto/x509v3/standard_exts.h"

static int test_standard_exts()
{
    size_t i;
    int prev = -1, good = 1;
    const X509V3_EXT_METHOD **tmp;

    tmp = standard_exts;
    for (i = 0; i < OSSL_NELEM(standard_exts); i++, tmp++) {
        if ((*tmp)->ext_nid < prev)
            good = 0;
        prev = (*tmp)->ext_nid;

    }
    if (!good) {
        tmp = standard_exts;
        fprintf(stderr, "Extensions out of order!\n");
        for (i = 0; i < STANDARD_EXTENSION_COUNT; i++, tmp++)
            fprintf(stderr, "%d : %s\n", (*tmp)->ext_nid,
                    OBJ_nid2sn((*tmp)->ext_nid));
    } else {
        fprintf(stderr, "Order OK\n");
    }

    return good;
}

void register_tests()
{
    ADD_TEST(test_standard_exts);
}
