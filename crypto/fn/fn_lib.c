/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include "fn_local.h"

#define SIZE_IS_BITS 0

static OSSL_FN *ossl_fn_new_internal(size_t size, bool securely)
{
#if SIZE_IS_BITS
    /*
     * Open question: should the input size be in bits?  In that case,
     * this adjustment is necessary.
     */

    /* Bits to bytes, rounded up */
    size = (size + CHAR_BITS - 1) / CHAR_BITS;
#endif

    /* bytes to number of limbs, rounded up */
    size_t limbs = (size + sizeof(OSSL_FN_ULONG) - 1) / sizeof(OSSL_FN_ULONG);

    /* Total size of the whole OSSL_FN */
    size_t totalsize = sizeof(OSSL_FN) + limbs * sizeof(OSSL_FN_ULONG);

    /*
     * If the size ends up being smaller than the bookkeeping struct,
     * we know that the size calculation has wrapped around and is
     * therefore invalid.  Also, we don't allow zero byte numbers.
     */
    if (totalsize <= sizeof(OSSL_FN))
        return NULL;

    OSSL_FN *ret = NULL;

    if (securely)
        ret = OPENSSL_secure_zalloc(totalsize);
    else
        ret = OPENSSL_zalloc(totalsize);

    if (ret != NULL) {
        ret->dsize = limbs;
        ret->is_dynamically_allocated = 1;
        ret->is_securely_allocated = securely;
    }
    return ret;
}

static void ossl_fn_free_internal(OSSL_FN *f, bool clear)
{
    if (f == NULL)
        return;

    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);
    size_t totalsize = limbssize + sizeof(OSSL_FN);

    if (f->is_dynamically_allocated) {
        if (f->is_securely_allocated)
            OPENSSL_secure_clear_free(f, totalsize);
        else if (clear)
            OPENSSL_clear_free(f, totalsize);
        else
            OPENSSL_free(f);
    } else if (clear) {
        OPENSSL_cleanse(&f->d, limbssize);
    }
}

OSSL_FN *OSSL_FN_new(size_t size)
{
    return ossl_fn_new_internal(size, false);
}

OSSL_FN *OSSL_FN_secure_new(size_t size)
{
    return ossl_fn_new_internal(size, true);
}

void OSSL_FN_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, false);
}

void OSSL_FN_clear_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, true);
}
