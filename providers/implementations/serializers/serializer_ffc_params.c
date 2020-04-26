/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Utility function for printing DSA/DH params. */

#include "prov/bio.h"
#include "serializer_local.h"

int ffc_params_prov_print(BIO *out, const FFC_PARAMS *ffc)
{
    if (ffc->nid != NID_undef) {
#ifndef OPENSSL_NO_DH
        const char *name = ffc_named_group_from_uid(ffc->nid);

        if (name == NULL)
            goto err;
        if (ossl_prov_bio_printf(out, "GROUP: %s\n", name) <= 0)
            goto err;
        return 1;
#else
        /* How could this be? We should not have a nid in a no-dh build. */
        goto err;
#endif
    }

    if (!ossl_prov_print_labeled_bignum(out, "P:   ", ffc->p))
        goto err;
    if (ffc->q != NULL) {
        if (!ossl_prov_print_labeled_bignum(out, "Q:   ", ffc->q))
            goto err;
    }
    if (!ossl_prov_print_labeled_bignum(out, "G:   ", ffc->g))
        goto err;
    if (ffc->j != NULL) {
        if (!ossl_prov_print_labeled_bignum(out, "J:   ", ffc->j))
            goto err;
    }
    if (ffc->seed != NULL) {
        if (!ossl_prov_print_labeled_buf(out, "SEED:", ffc->seed, ffc->seedlen))
            goto err;
    }
    if (ffc->gindex != -1) {
        if (ossl_prov_bio_printf(out, "gindex: %d\n", ffc->gindex) <= 0)
            goto err;
    }
    if (ffc->pcounter != -1) {
        if (ossl_prov_bio_printf(out, "pcounter: %d\n", ffc->pcounter) <= 0)
            goto err;
    }
    if (ffc->h != 0) {
        if (ossl_prov_bio_printf(out, "h: %d\n", ffc->h) <= 0)
            goto err;
    }
    return 1;
err:
    return 0;
}
