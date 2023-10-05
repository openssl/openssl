/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/lms.h"
#include "internal/refcount.h"

LMS_SIG *ossl_lms_sig_new(void)
{
    LMS_SIG *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    if (!CRYPTO_NEW_REF(&ret->references, 1))
        goto err;

    return ret;
err:
    if (ret != NULL)
        CRYPTO_FREE_REF(&ret->references);
    OPENSSL_free(ret);
    return NULL;
}

void ossl_lms_sig_free(LMS_SIG *sig)
{
    int i;

    if (sig == NULL)
        return;

    CRYPTO_DOWN_REF(&sig->references, &i);
    REF_PRINT_COUNT("LMS_SIG", sig);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    CRYPTO_FREE_REF(&sig->references);
    OPENSSL_free(sig);
}

int ossl_lms_sig_up_ref(LMS_SIG *sig)
{
    int i;

    if (CRYPTO_UP_REF(&sig->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("LMS_SIG", sig);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}
