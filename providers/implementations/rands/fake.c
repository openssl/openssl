/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A simple fake RNG for use in testing.  Not thread-safe.
 */

#include <string.h>
#include <openssl/core_names.h>
#include <crypto/rand.h>
#include <crypto/rand.h>
#include "drbg_local.h"

typedef struct fake_rand_state_st {
    const char *values;
    int size;
    int curr;
} FAKE_RAND_STATE;

static int get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 255))
        return 0;

    return 1;
}

static int generate(void *vctx, unsigned char *out, size_t outlen,
        unsigned int strength, int prediction_resistance,
        const unsigned char *addin, size_t addin_len)
{
    FAKE_RAND_STATE *s = vctx;

    if (s->values == NULL) {
        unsigned char val = 1;

        for (; outlen != 0; --outlen)
            *out++ = val++;
    } else {
        for ( ; outlen != 0; --outlen) {
            if (s->curr >= s->size)
                s->curr = 0;
            *out++ = s->values[s->curr++];
        }
    }
    return 1;
}

static void freectx(void *vdrbg)
{
}

EVP_RAND_CTX *RAND_make_fake(const char *values)
{
    static FAKE_RAND_STATE state;
    static EVP_RAND method;
    static EVP_RAND_CTX simple;

    method.get_ctx_params = get_ctx_params;
    method.freectx = freectx;
    method.generate = generate;
    state.values = values;
    state.size = state.curr = 0;
    if (values != NULL)
        state.size = (int)strlen(values);
    simple.meth = &method;
    simple.data = &state;
    simple.refcnt = 10; /* arbitrarily big */

    return &simple;
}
