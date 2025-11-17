/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <limits.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include "internal/common.h"
#include "fn_local.h"

static OSSL_FN *ossl_fn_new_internal(size_t limbs, bool securely)
{
    /* Total size of the whole OSSL_FN, in bytes */
    size_t totalsize = ossl_fn_totalsize(limbs);
    if (totalsize == 0)
        return NULL;

    OSSL_FN *ret = NULL;

    if (securely)
        ret = OPENSSL_secure_zalloc(totalsize);
    else
        ret = OPENSSL_zalloc(totalsize);

    if (ret != NULL) {
        ret->dsize = (int)limbs;
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
        OPENSSL_cleanse(f->d, limbssize);
    }
}

OSSL_FN *OSSL_FN_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, false);
}

OSSL_FN *OSSL_FN_secure_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, true);
}

OSSL_FN *OSSL_FN_new_bytes(size_t size)
{
    return OSSL_FN_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_secure_new_bytes(size_t size)
{
    return OSSL_FN_secure_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_new_bits(size_t size)
{
    return OSSL_FN_new_bytes(ossl_fn_bits_to_bytes(size));
}

OSSL_FN *OSSL_FN_secure_new_bits(size_t size)
{
    return OSSL_FN_secure_new_bytes(ossl_fn_bits_to_bytes(size));
}

void OSSL_FN_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, false);
}

void OSSL_FN_clear_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, true);
}

void OSSL_FN_clear(OSSL_FN *f)
{
    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);

    OPENSSL_cleanse(f->d, limbssize);
}
