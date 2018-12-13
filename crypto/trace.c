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

#ifndef OPENSSL_NO_TRACE

/*-
 * INTERNAL BIO IMPLEMENTATION
 *
 * For our own flexibility, we have an internal BIO whose only job is
 * to call the application provided hooks for trace and debug output.
 */
static int hookwrite(BIO *h, const char *buf, size_t num, size_t *written);
static int hookputs(BIO *h, const char *str);
static const BIO_METHOD hook_method = {
    BIO_TYPE_SOURCE_SINK,
    "memory buffer",
    hookwrite,
    NULL,                        /* old write */
    NULL,                        /* read_ex */
    NULL,                        /* read */
    hookputs,
    NULL,                        /* gets */
    NULL,                        /* ctrl */
    NULL,                        /* create */
    NULL,                        /* free */
    NULL,                        /* callback_ctrl */
};

/* This structure connects the BIO to the corresponding hook function */
struct bio_hook_st {
    OSSL_tracer_fn hook;
    void *hookdata;
};

static int hookwrite(BIO *h, const char *buf, size_t num, size_t *written)
{
    struct bio_hook_st *biodata = (struct bio_hook_st *)BIO_get_data(h);
    size_t cnt = biodata->hook(buf, num, biodata->hookdata);

    *written = cnt;
    return cnt != 0;
}

static int hookputs(BIO *h, const char *str)
{
    size_t written;

    if (hookwrite(h, str, strlen(str), &written))
        return (int)written;

    return EOF;
}

#endif

/* Helper struct and macro to get name string to number mapping */
struct namenum_st {
    const char * const name;
    const int num;
};
#define DEFNAME(typename)       { #typename, OSSL_DEBUG_##typename }

/*-
 * TRACE
 */

static const struct namenum_st tracenames[] = {
    DEFNAME(DEFAULT),
};

int OSSL_trace_get_type(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(tracenames); i++)
        if (strcasecmp(name, tracenames[i].name) == 0)
            return tracenames[i].num;
    return -1;                   /* or should that be 0, i.e. DEFAULT? */
}

#ifndef OPENSSL_NO_TRACE

/* We store one trace BIO for each trace type */
static struct bio_hook_st trace_data[OSSL_TRACE_NUM] = { { NULL, NULL }, };
static BIO *trace_bio[OSSL_TRACE_NUM] = { NULL, };

#endif

void OSSL_trace_set(int type, OSSL_tracer_fn fn, void *hookdata)
{
#ifndef OPENSSL_NO_TRACE
    if (trace_data[type].hook != NULL && fn == NULL) {
        BIO_free(trace_bio[type]);
        trace_bio[type] = NULL;
    }

    trace_data[type].hook = fn;
    trace_data[type].hookdata = hookdata;

    if (trace_bio[type] == NULL
        && fn != NULL
        && (trace_bio[type] = BIO_new(&hook_method)) != NULL)
        BIO_set_data(trace_bio[type], &trace_data[type]);
#endif
}

#ifndef OPENSSL_NO_TRACE

int OSSL_trace_is_set(int type)
{
    return OSSL_trace_bio(type) != NULL;
}

BIO *OSSL_trace_bio(int type)
{
    if (trace_bio[type] != NULL)
        return trace_bio[type];
    return trace_bio[OSSL_TRACE_DEFAULT];
}

#endif

int OSSL_trace(int type, char *fmt, ...)
{
    int ret = 1;
#ifndef OPENSSL_NO_TRACE
    va_list args;

    va_start(args, fmt);
    ret = OSSL_vtrace(type, fmt, args);
    va_end(args);
#endif

    return ret;
}

int OSSL_vtrace(int type, char *fmt, va_list args)
{
    BIO *bio = OSSL_trace_bio(type);

    if (bio != NULL)
        return BIO_vprintf(bio, fmt, args) >= 0;
    return 1;
}

/*-
 * DEBUG
 */

static const struct namenum_st debugnames[] = {
    DEFNAME(DEFAULT),
    DEFNAME(INIT),
    DEFNAME(TLS),
    DEFNAME(SSL),
    DEFNAME(TLS_CIPHER),
    DEFNAME(SSL_CIPHER),
    DEFNAME(ENGINE_CONF),
    DEFNAME(ENGINE_TABLE),
    DEFNAME(ENGINE_REF_COUNT),
    DEFNAME(PKCS5V2),
    DEFNAME(PKCS12_KEYGEN),
};

int OSSL_debug_get_type(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(debugnames); i++)
        if (strcasecmp(name, debugnames[i].name) == 0)
            return debugnames[i].num;
    return -1;                   /* or should that be 0, i.e. DEFAULT? */
}

#ifndef OPENSSL_NO_TRACE

/* We store one trace BIO for each debug type */
static struct bio_hook_st debug_data[OSSL_DEBUG_NUM] = { { NULL, NULL }, };
static BIO *debug_bio[OSSL_DEBUG_NUM] = { NULL, };

#endif

void OSSL_debug_set(int type, OSSL_tracer_fn fn, void *hookdata)
{
#ifndef OPENSSL_NO_TRACE
    if (debug_data[type].hook != NULL && fn == NULL) {
        BIO_free(debug_bio[type]);
        debug_bio[type] = NULL;
    }

    debug_data[type].hook = fn;
    debug_data[type].hookdata = hookdata;

    if (debug_bio[type] == NULL
        && fn != NULL
        && (debug_bio[type] = BIO_new(&hook_method)) != NULL)
        BIO_set_data(debug_bio[type], &debug_data[type]);
#endif
}

#ifndef OPENSSL_NO_TRACE

int OSSL_debug_is_set(int type)
{
    return OSSL_debug_bio(type) != NULL;
}

BIO *OSSL_debug_bio(int type)
{
    if (debug_bio[type] != NULL)
        return debug_bio[type];
    return debug_bio[OSSL_DEBUG_DEFAULT];
}

#endif

int OSSL_debug(int type, char *fmt, ...)
{
    int ret = 1;
#ifndef OPENSSL_NO_TRACE
    va_list args;

    va_start(args, fmt);
    ret = OSSL_vdebug(type, fmt, args);
    va_end(args);
#endif

    return ret;
}

int OSSL_vdebug(int type, char *fmt, va_list args)
{
    BIO *bio = OSSL_debug_bio(type);

    if (bio != NULL)
        return BIO_vprintf(bio, fmt, args) >= 0;
    return 1;
}
