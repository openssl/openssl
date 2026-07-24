/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crau.h>
#include "crypto/context.h"
#include "internal/cryptlib.h"
#include "internal/numbers.h"

#ifndef OPENSSL_NO_CRAU
#include <sys/sdt.h>

#define CRAU_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size) \
    DTRACE_PROBE4(crypto_auditing, new_context_with_data, context, parent, \
        array_ptr, array_size)

#define CRAU_DATA(context, array_ptr, array_size) \
    DTRACE_PROBE3(crypto_auditing, data, context, array_ptr, array_size)

#else /* OPENSSL_NO_CRAU */

#define CRAU_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size)
#define CRAU_DATA(context, array_ptr, array_size)

#endif /* OPENSSL_NO_CRAU */

typedef struct crau_context_st {
    /* When entering a new context, current will be updated to
     * &base[n+1]; when leaving the context it will be &base[n].  */
    void **current;
    void *base[1];
} CRAU_CONTEXT;

#define CRAU_THREAD_CONTEXT(ptr) \
    ((long)(ptr) ^ (long)CRYPTO_THREAD_get_current_id())

void *ossl_crau_set_context_new(OSSL_LIB_CTX *ctx)
{
    CRAU_CONTEXT *c;

    c = OPENSSL_zalloc(sizeof(*c));
    if (c == NULL)
        return NULL;
    c->current = &c->base[0];
    return c;
}

void ossl_crau_set_context_free(void *c)
{
    OPENSSL_free(c);
}

/* The maximum number of events which can be emitted at once. */
#define CRAU_MAX_DATA_ELEMS 16

/* Generic data structure that represents an event. The KEY_PTR field
 * points to the name of the event key, and the VALUE_PTR field points
 * to the value.
 *
 * The VALUE_SIZE field is set depending on the type of the value. If
 * the value is a machine word, it is set to (unsigned long)-2.  If
 * the value is a NUL-terminated string, it is set to (unsigned
 * long)-1. Otherwise, it is set to the actual size of the value.
 */
struct crau_data {
    char *key_ptr;
    void *value_ptr;
    unsigned long value_size;
};

#ifndef OPENSSL_NO_CRAU
static int ossl_params_to_crau_data(const OSSL_PARAM params[],
    struct crau_data data[],
    size_t *data_size)
{
    size_t i;

    if (params == NULL) {
        *data_size = 0;
        return 1;
    }

    for (i = 0; params[i].key != NULL && i < *data_size; i++) {
        data[i].key_ptr = (char *)params[i].key;
        int ival;
        unsigned int uval;

        switch (params[i].data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_get_int(&params[i], &ival))
                return 0;
            data[i].value_ptr = (void *)(long)ival;
            data[i].value_size = (unsigned long)-2;
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            if (!OSSL_PARAM_get_uint(&params[i], &uval) || uval > INT_MAX)
                return 0;
            data[i].value_ptr = (void *)(long)uval;
            data[i].value_size = (unsigned long)-2;
            break;
        case OSSL_PARAM_UTF8_STRING:
            data[i].value_ptr = params[i].data;
            data[i].value_size = (unsigned long)-1;
            break;
        case OSSL_PARAM_OCTET_STRING:
            data[i].value_ptr = params[i].data;
            data[i].value_size = params[i].data_size;
            break;
        default:
            return 0;
        }
    }

    *data_size = i;
    return 1;
}

static CRAU_CONTEXT *get_crau_context(OSSL_LIB_CTX *libctx)
{
    return ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_CRAU_CONTEXT_INDEX);
}
#endif

void OSSL_CRAU_enter(OSSL_LIB_CTX *libctx,
    const char *name,
    const OSSL_PARAM params[])
{
#ifndef OPENSSL_NO_CRAU
    struct crau_data data[CRAU_MAX_DATA_ELEMS];
    size_t data_size = CRAU_MAX_DATA_ELEMS - 1;
    CRAU_CONTEXT *ctx;

    ctx = get_crau_context(libctx);
    if (ctx != NULL
        && ossl_params_to_crau_data(params, data, &data_size)) {
        const void *parent = ctx->current++;

        data[data_size].key_ptr = "name";
        data[data_size].value_ptr = (void *)name;
        data[data_size].value_size = (unsigned long)-1;
        data_size++;

        CRAU_NEW_CONTEXT_WITH_DATA(CRAU_THREAD_CONTEXT(ctx->current),
            CRAU_THREAD_CONTEXT(parent),
            data, data_size);
    }
#endif
}

void OSSL_CRAU_data(OSSL_LIB_CTX *libctx,
    const OSSL_PARAM params[])
{
#ifndef OPENSSL_NO_CRAU
    struct crau_data data[CRAU_MAX_DATA_ELEMS];
    size_t data_size = CRAU_MAX_DATA_ELEMS;
    CRAU_CONTEXT *ctx;

    ctx = get_crau_context(libctx);
    if (ctx != NULL
        && ossl_params_to_crau_data(params, data, &data_size)) {
        CRAU_DATA(CRAU_THREAD_CONTEXT(ctx->current), data, data_size);
    }
#endif
}

void OSSL_CRAU_leave(OSSL_LIB_CTX *libctx)
{
#ifndef OPENSSL_NO_CRAU
    CRAU_CONTEXT *ctx;

    ctx = get_crau_context(libctx);
    if (ctx != NULL && ctx->current != &ctx->base[0])
        ctx->current--;
#endif
}
