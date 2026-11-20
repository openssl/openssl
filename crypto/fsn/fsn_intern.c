/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "crypto/fsn_intern.h"
#include "crypto/fsnerr.h"
#include "fsn_local.h"
#include <openssl/err.h>

int ossl_fsn_set_words(OSSL_FSN *f, const OSSL_FSN_ULONG *words, size_t limbs)
{
    if (ossl_unlikely(f == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FSN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((size_t)f->dsize < limbs) {
        ERR_raise(ERR_LIB_OSSL_FSN, OSSL_FSN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    memcpy(f->d, words, sizeof(OSSL_FSN_ULONG) * limbs);
    memset(f->d + limbs, 0, sizeof(OSSL_FSN_ULONG) * (f->dsize - limbs));
    return 1;
}

const OSSL_FSN_ULONG *ossl_fsn_get_words(const OSSL_FSN *f)
{
    if (ossl_unlikely(f == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FSN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return f->d;
}

size_t ossl_fsn_get_dsize(const OSSL_FSN *f)
{
    return f->dsize;
}

bool ossl_fsn_is_dynamically_allocated(const OSSL_FSN *f)
{
    return f->is_dynamically_allocated;
}

bool ossl_fsn_is_securely_allocated(const OSSL_FSN *f)
{
    return f->is_securely_allocated;
}
