/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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
static long trace_ctrl(BIO *channel, int cmd, long argl, void *argp);
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
    trace_ctrl,                  /* ctrl */
    NULL,                        /* create */
    trace_free,                  /* free */
    NULL,                        /* callback_ctrl */
};

struct trace_data_st {
    OSSL_trace_cb callback;
    int category;
    void *data;
};

static int trace_write(BIO *channel,
                       const char *buf, size_t num, size_t *written)
{
    struct trace_data_st *ctx = BIO_get_data(channel);
    size_t cnt = ctx->callback(buf, num, ctx->category, OSSL_TRACE_CTRL_DURING,
                               ctx->data);

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

static long trace_ctrl(BIO *channel, int cmd, long argl, void *argp)
{
    struct trace_data_st *ctx = BIO_get_data(channel);

    switch (cmd) {
    case OSSL_TRACE_CTRL_BEGIN:
    case OSSL_TRACE_CTRL_END:
        /* We know that the callback is likely to return 0 here */
        ctx->callback("", 0, ctx->category, cmd, ctx->data);
        return 1;
    default:
        break;
    }
    return -2;                   /* Unsupported */
}

static int trace_free(BIO *channel)
{
    if (channel == NULL)
        return 0;
    OPENSSL_free(BIO_get_data(channel));
    return 1;
}
#endif

/*-
 * TRACE
 */

/* Helper struct and macro to get name string to number mapping */
struct trace_category_st {
    const char * const name;
    const int num;
};
#define TRACE_CATEGORY_(name)       { #name, OSSL_TRACE_CATEGORY_##name }

static const struct trace_category_st trace_categories[] = {
    TRACE_CATEGORY_(ANY),
    TRACE_CATEGORY_(INIT),
    TRACE_CATEGORY_(TLS),
    TRACE_CATEGORY_(TLS_CIPHER),
    TRACE_CATEGORY_(ENGINE_CONF),
    TRACE_CATEGORY_(ENGINE_TABLE),
    TRACE_CATEGORY_(ENGINE_REF_COUNT),
    TRACE_CATEGORY_(PKCS5V2),
};

const char *OSSL_trace_get_category_name(int num)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(trace_categories); i++)
        if (trace_categories[i].num == num)
            return trace_categories[i].name;
    return NULL; /* not found */
}

int OSSL_trace_get_category_num(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(trace_categories); i++)
        if (strcasecmp(name, trace_categories[i].name) == 0)
            return trace_categories[i].num;
    return -1; /* not found */
}

#ifndef OPENSSL_NO_TRACE

/* We use one trace channel for each trace category */
static struct {
    enum { t_channel, t_callback } type;
    BIO *bio;
    char *prefix;
    char *suffix;
} trace_channels[OSSL_TRACE_CATEGORY_NUM] = {
    { 0, NULL, NULL, NULL },
};

#endif

int ossl_trace_init(void)
{
#ifndef OPENSSL_NO_TRACE
    trace_lock = CRYPTO_THREAD_lock_new();
    if (trace_lock != NULL)
        return 1;
#endif

    return 0;
}

void ossl_trace_cleanup(void)
{
#ifndef OPENSSL_NO_TRACE
    int category;

    for (category = 0; category < OSSL_TRACE_CATEGORY_NUM; category++)
        OSSL_trace_set_channel(category, NULL);
    CRYPTO_THREAD_lock_free(trace_lock);
#endif
}

int OSSL_trace_set_channel(int category, BIO *channel)
{
#ifndef OPENSSL_NO_TRACE
    BIO *prev_channel;

    if (category < 0 || category >= OSSL_TRACE_CATEGORY_NUM)
        goto err;

    prev_channel = trace_channels[category].bio;

    if (prev_channel != NULL) {
        BIO_free(prev_channel);
        trace_channels[category].bio = NULL;
    }

    if (channel == NULL)
        return 1;                /* Done */

    trace_channels[category].bio = channel;
    trace_channels[category].type = t_channel;

    return 1;

 err:
#endif

    return 0;
}

int OSSL_trace_set_callback(int category, OSSL_trace_cb callback, void *data)
{
#ifndef OPENSSL_NO_TRACE
    BIO *channel = trace_channels[category].bio;
    struct trace_data_st *trace_data = NULL;

    if (channel != NULL) {
        BIO_free(channel);
        trace_channels[category].bio = NULL;
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
    trace_data->category = category;
    trace_data->data = data;

    BIO_set_data(channel, trace_data);

    trace_channels[category].bio = channel;
    trace_channels[category].type = t_callback;

    return 1;

 err:
    BIO_free(channel);
    OPENSSL_free(trace_data);
#endif

    return 0;
}

int OSSL_trace_set_prefix(int category, const char *prefix)
{
#ifndef OPENSSL_NO_TRACE
    char *curr_prefix = trace_channels[category].prefix;

    if (curr_prefix != NULL) {
        OPENSSL_free(curr_prefix);
        trace_channels[category].prefix = NULL;
    }

    if (prefix == NULL)
        return 1;                /* Done */

    curr_prefix = OPENSSL_strdup(prefix);
    if (curr_prefix == NULL)
        goto err;

    trace_channels[category].prefix = curr_prefix;

    return 1;

 err:
#endif

    return 0;
}

int OSSL_trace_set_suffix(int category, const char *suffix)
{
#ifndef OPENSSL_NO_TRACE
    char *curr_suffix = trace_channels[category].suffix;

    if (curr_suffix != NULL) {
        OPENSSL_free(curr_suffix);
        trace_channels[category].suffix = NULL;
    }

    if (suffix == NULL)
        return 1; /* done */

    curr_suffix = OPENSSL_strdup(suffix);
    if (curr_suffix == NULL)
        goto err;

    trace_channels[category].suffix = curr_suffix;

    return 1;

 err:
#endif

    return 0;
}

#ifndef OPENSSL_NO_TRACE
static int ossl_trace_get_category(int category)
{
    if (category < 0 || category >= OSSL_TRACE_CATEGORY_NUM)
        return -1;
    if (trace_channels[category].bio != NULL)
        return category;
    return OSSL_TRACE_CATEGORY_ANY;
}
#endif

int OSSL_trace_enabled(int category)
{
    int ret = 0;
#ifndef OPENSSL_NO_TRACE
    category = ossl_trace_get_category(category);
    ret = trace_channels[category].bio != NULL;
#endif
    return ret;
}

BIO *OSSL_trace_begin(int category)
{
    BIO *channel = NULL;
#ifndef OPENSSL_NO_TRACE
    char *prefix = NULL;

    category = ossl_trace_get_category(category);
    channel = trace_channels[category].bio;
    prefix = trace_channels[category].prefix;

    if (channel != NULL) {
        CRYPTO_THREAD_write_lock(trace_lock);
        current_channel = channel;
        switch (trace_channels[category].type) {
        case t_channel:
            if (prefix != NULL) {
                (void)BIO_puts(channel, prefix);
                (void)BIO_puts(channel, "\n");
            }
            break;
        case t_callback:
            (void)BIO_ctrl(channel, OSSL_TRACE_CTRL_BEGIN,
                           prefix == NULL ? 0 : strlen(prefix), prefix);
            break;
        }
    }
#endif
    return channel;
}

void OSSL_trace_end(int category, BIO * channel)
{
#ifndef OPENSSL_NO_TRACE
    char *suffix = NULL;

    category = ossl_trace_get_category(category);
    suffix = trace_channels[category].suffix;
    if (channel != NULL
        && ossl_assert(channel == current_channel)) {
        (void)BIO_flush(channel);
        switch (trace_channels[category].type) {
        case t_channel:
            if (suffix != NULL) {
                (void)BIO_puts(channel, suffix);
                (void)BIO_puts(channel, "\n");
            }
            break;
        case t_callback:
            (void)BIO_ctrl(channel, OSSL_TRACE_CTRL_END,
                           suffix == NULL ? 0 : strlen(suffix), suffix);
            break;
        }
        current_channel = NULL;
        CRYPTO_THREAD_unlock(trace_lock);
    }
#endif
}
