/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "crypto/fxn_intern.h"
#include "crypto/fxnerr.h"
#include "fxn_local.h"
#include <openssl/err.h>

int ossl_fxn_set_words(OSSL_FXN *f, const OSSL_FXN_ULONG *words, size_t limbs)
{
    if (ossl_unlikely(f == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((size_t)f->dsize < limbs) {
        ERR_raise(ERR_LIB_OSSL_FXN, OSSL_FXN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    memcpy(f->d, words, sizeof(OSSL_FXN_ULONG) * limbs);
    memset(f->d + limbs, 0, sizeof(OSSL_FXN_ULONG) * (f->dsize - limbs));
    return 1;
}

const OSSL_FXN_ULONG *ossl_fxn_get_words(const OSSL_FXN *f)
{
    if (ossl_unlikely(f == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return f->d;
}

size_t ossl_fxn_get_dsize(const OSSL_FXN *f)
{
    return f->dsize;
}

bool ossl_fxn_is_dynamically_allocated(const OSSL_FXN *f)
{
    return f->is_dynamically_allocated;
}

bool ossl_fxn_is_securely_allocated(const OSSL_FXN *f)
{
    return f->is_securely_allocated;
}
