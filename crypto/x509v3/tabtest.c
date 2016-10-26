/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple program to check the ext_dat.h is correct and print out problems if
 * it is not.
 */

#include <stdio.h>

#include <openssl/x509v3.h>

#include "x509v3_lcl.h"
#include "ext_dat.h"

#include "e_os.h"

int main()
{
    size_t i;
    int prev = -1, bad = 0;
    const X509V3_EXT_METHOD **tmp;

    tmp = standard_exts;
    for (i = 0; i < OSSL_NELEM(standard_exts); i++, tmp++) {
        if ((*tmp)->ext_nid < prev)
            bad = 1;
        prev = (*tmp)->ext_nid;

    }
    if (bad == 1) {
        tmp = standard_exts;
        fprintf(stderr, "Extensions out of order!\n");
        for (i = 0; i < OSSL_NELEM(standard_exts); i++, tmp++)
            printf("%d : %s\n", (*tmp)->ext_nid, OBJ_nid2sn((*tmp)->ext_nid));
    } else
        fprintf(stderr, "Order OK\n");

    exit(bad);
}
