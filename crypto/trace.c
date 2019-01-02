/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/trace.h>
#include "internal/bio.h"
#include "internal/nelem.h"
#include "internal/cryptlib_int.h"

#include "e_os.h"                /* strcasecmp for Windows */

#ifndef OPENSSL_NO_TRACE

static CRYPTO_RWLOCK *trace_lock = NULL;

static const BIO  *current_channel = NULL;

static BIO *ossl_trace_get_channel(int category);

/*-
 * INTERNAL TRACE CHANNEL IMPLEMENTATION
 *
 * For our own flexibility, all trace categories are associated with a
 * BIO sink object, also called the trace channel. Instead of a BIO object,
 * the application can also provide a callback function, in which case an
 * internal trace channel is attached, which simply calls the registered
 * callback function.
 */
static int trace_write(BIO *b, const char *buf,
                               size_t num, size_t *written);
static int trace_puts(BIO *b, const char *str);
static int trace_free(BIO *b);

static const BIO_METHOD trace_method = {
    BIO_TYPE_SOURCE_SINK,
    "trace",
    trace_write,
    NULL,                        /* old write */
    NULL,                        /* read_ex */
    NULL,                        /* read */
    trace_puts,
    NULL,                        /* gets */
    NULL,                        /* ctrl */
    NULL,                        /* create */
    trace_free,                  /* free */
    NULL,                        /* callback_ctrl */
};

struct trace_data_st {
    OSSL_trace_cb callback;
    void *data;
};

static int trace_free(BIO *channel)
{
    if (channel == NULL)
        return 0;
    OPENSSL_free(BIO_get_data(channel));
    return 1;
}

static int trace_write(BIO *channel,
                       const char *buf, size_t num, size_t *written)
{
    struct trace_data_st *ctx = BIO_get_data(channel);
    size_t cnt = ctx->callback(buf, num, ctx->data);

    *written = cnt;
    return cnt != 0;
}

static int trace_puts(BIO *channel, const char *str)
{
    size_t written;

    if (trace_write(channel, str, strlen(str), &written))
        return (int)written;

    return EOF;
}


/* Helper struct and macro to get name string to number mapping */
struct trace_category_st {
    const char * const name;
    const int num;
};
#define TRACE_CATEGORY_(name)       { #name, OSSL_TRACE_CATEGORY_##name }

/*-
 * TRACE
 */

static const struct trace_category_st trace_categories[] = {
    TRACE_CATEGORY_(ANY),
    TRACE_CATEGORY_(TRACE),
    TRACE_CATEGORY_(INIT),
    TRACE_CATEGORY_(TLS),
    TRACE_CATEGORY_(SSL),
    TRACE_CATEGORY_(TLS_CIPHER),
    TRACE_CATEGORY_(SSL_CIPHER),
    TRACE_CATEGORY_(ENGINE_CONF),
    TRACE_CATEGORY_(ENGINE_TABLE),
    TRACE_CATEGORY_(ENGINE_REF_COUNT),
    TRACE_CATEGORY_(PKCS5V2),
    TRACE_CATEGORY_(PKCS12_KEYGEN),
    TRACE_CATEGORY_(PKCS12_DECRYPT),
    TRACE_CATEGORY_(X509V3_POLICY),
    TRACE_CATEGORY_(BN_CTX),
};

int OSSL_trace_get_category(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(trace_categories); i++)
        if (strcasecmp(name, trace_categories[i].name) == 0)
            return trace_categories[i].num;
    return -1; /* not found */
}

/* We use one trace channel for each trace category */
static BIO *trace_channels[OSSL_TRACE_CATEGORY_NUM] = {
    NULL,
};

int ossl_trace_init(void)
{
    trace_lock = CRYPTO_THREAD_lock_new();
    if (trace_lock == NULL)
        return 0;

    return 1;
}

void ossl_trace_cleanup(void)
{
    CRYPTO_THREAD_lock_free(trace_lock);
}

int OSSL_trace_set_channel(int category, BIO *channel)
{
    BIO *prev_channel = trace_channels[category];

    if (prev_channel != NULL) {
        OSSL_TRACE2(TRACE, "Detach channel %p from category '%s'\n",
                    (void*)prev_channel, trace_categories[category].name);
        BIO_free(prev_channel);
        trace_channels[category] = NULL;
    }

    if (channel == NULL)
        return 1; /* done */

    trace_channels[category] = channel;
    OSSL_TRACE2(TRACE, "Attach channel %p to category '%s'\n",
                (void*)channel, trace_categories[category].name);

    return 1;
}

int OSSL_trace_set_callback(int category, OSSL_trace_cb callback, void *data)
{
    BIO *channel = trace_channels[category];
    struct trace_data_st *trace_data = NULL;

    if (channel != NULL) {
        OSSL_TRACE2(TRACE, "Detach channel %p from category '%s'\n",
                    (void*)channel, trace_categories[category].name);
        BIO_free(channel);
        trace_channels[category] = NULL;
    }

    if (callback == NULL)
        return 1; /* done */

    channel = BIO_new(&trace_method);
    if (channel == NULL)
        goto err;

    trace_data = OPENSSL_zalloc(sizeof(struct trace_data_st));
    if (trace_data == NULL)
        goto err;

    trace_data->callback = callback;
    trace_data->data = data;

    BIO_set_data(channel, trace_data);

    trace_channels[category] = channel;
    OSSL_TRACE2(TRACE, "Attach channel %p to category '%s' (with callback)\n",
                (void*)channel, trace_categories[category].name);

    return 1;

 err:
    BIO_free(channel);
    OPENSSL_free(trace_data);

    return 0;
}

static BIO *ossl_trace_get_channel(int category)
{
    if (trace_channels[category] != NULL)
        return trace_channels[category];
    return trace_channels[OSSL_TRACE_CATEGORY_ANY];
}

int OSSL_trace_enabled(int category)
{
    return ossl_trace_get_channel(category) != NULL;
}

BIO *OSSL_trace_begin(int category)
{
    BIO *channel = ossl_trace_get_channel(category);
    if (channel != NULL) {
        CRYPTO_THREAD_write_lock(trace_lock);

        BIO_printf(channel, "TRC[%lx]:%s: ",
                   (unsigned long)CRYPTO_THREAD_get_current_id(),
                   trace_categories[category].name
                   );

        current_channel = channel;
    }

    return channel;
}

void OSSL_trace_end(int category, BIO * channel)
{
    if (channel != NULL
        && ossl_assert(channel == current_channel)) {
        (void)BIO_flush(channel);
        current_channel = NULL;
        CRYPTO_THREAD_unlock(trace_lock);
    }
}
#endif /*ifndef OPENSSL_NO_TRACE*/
