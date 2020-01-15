/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/self_test.h>
#include "internal/cryptlib.h"

typedef struct self_test_cb_st
{
    OSSL_CALLBACK *cb;
    void *cbarg;
} SELF_TEST_CB;

static void *self_test_set_callback_new(OPENSSL_CTX *ctx)
{
    SELF_TEST_CB *stcb;

    stcb = OPENSSL_zalloc(sizeof(*stcb));
    return stcb;
}

static void self_test_set_callback_free(void *stcb)
{
    OPENSSL_free(stcb);
}

static const OPENSSL_CTX_METHOD self_test_set_callback_method = {
    self_test_set_callback_new,
    self_test_set_callback_free,
};

static SELF_TEST_CB *get_self_test_callback(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_SELF_TEST_CB_INDEX,
                                &self_test_set_callback_method);
}

void OSSL_SELF_TEST_set_callback(OPENSSL_CTX *libctx, OSSL_CALLBACK *cb,
                                 void *cbarg)
{
    SELF_TEST_CB *stcb = get_self_test_callback(libctx);

    if (stcb != NULL) {
        stcb->cb = cb;
        stcb->cbarg = cbarg;
    }
}
void OSSL_SELF_TEST_get_callback(OPENSSL_CTX *libctx, OSSL_CALLBACK **cb,
                                 void **cbarg)
{
    SELF_TEST_CB *stcb = get_self_test_callback(libctx);

    if (cb != NULL)
        *cb = (stcb != NULL ? stcb->cb : NULL);
    if (cbarg != NULL)
        *cbarg = (stcb != NULL ? stcb->cbarg : NULL);
}
