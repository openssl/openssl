/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include "fake_storeprov.h"

/*
 * A minimal store loader that emits OSSL_STORE_INFO_NAME objects, so that
 * no decoders or other providers are needed to exercise the OSSL_STORE API.
 * The URI part after the scheme selects the loader behaviour, see the
 * FAKE_STORE_CMD_* macros.
 */

struct fake_store_ctx_st {
    int remaining;
    int fail_params;
    int expected_type;
};

static unsigned int seen_params = 0;
static char last_deleted[256] = "";

unsigned int fake_store_get_seen_params(void)
{
    return seen_params;
}

void fake_store_clear_state(void)
{
    seen_params = 0;
    last_deleted[0] = '\0';
}

const char *fake_store_get0_last_deleted(void)
{
    return last_deleted;
}

static OSSL_FUNC_store_open_fn fake_store_open;
static OSSL_FUNC_store_open_ex_fn fake_store_open_ex;
static OSSL_FUNC_store_attach_fn fake_store_attach;
static OSSL_FUNC_store_settable_ctx_params_fn fake_store_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn fake_store_set_ctx_params;
static OSSL_FUNC_store_load_fn fake_store_load;
static OSSL_FUNC_store_eof_fn fake_store_eof;
static OSSL_FUNC_store_close_fn fake_store_close;
static OSSL_FUNC_store_delete_fn fake_store_delete;

static void *fake_store_open(void *provctx, const char *uri)
{
    struct fake_store_ctx_st *ctx;
    const char *cmd;

    if ((cmd = strchr(uri, ':')) == NULL)
        return NULL;
    cmd++;

    if (strcmp(cmd, FAKE_STORE_CMD_OPEN_FAIL) == 0)
        return NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->remaining = strcmp(cmd, FAKE_STORE_CMD_TWO_NAMES) == 0 ? 2 : 1;
    ctx->fail_params = strcmp(cmd, FAKE_STORE_CMD_PARAMS_FAIL) == 0;
    return ctx;
}

static void *fake_store_open_ex(void *provctx, const char *uri,
    const OSSL_PARAM params[],
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct fake_store_ctx_st *ctx = fake_store_open(provctx, uri);

    if (ctx != NULL && params != NULL
        && !fake_store_set_ctx_params(ctx, params)) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void *fake_store_attach(void *provctx, OSSL_CORE_BIO *in)
{
    struct fake_store_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->remaining = 1;
    return ctx;
}

static const OSSL_PARAM fake_store_settable_params_list[] = {
    OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
    OSSL_PARAM_BN(OSSL_STORE_PARAM_SERIAL, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *fake_store_settable_ctx_params(void *provctx)
{
    return fake_store_settable_params_list;
}

static int fake_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    struct fake_store_ctx_st *ctx = loaderctx;
    const OSSL_PARAM *p;

    if (ctx->fail_params)
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT)) != NULL) {
        if (!OSSL_PARAM_get_int(p, &ctx->expected_type))
            return 0;
        seen_params |= FAKE_STORE_SEEN_EXPECT;
    }
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT) != NULL)
        seen_params |= FAKE_STORE_SEEN_SUBJECT;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ISSUER) != NULL)
        seen_params |= FAKE_STORE_SEEN_ISSUER;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SERIAL) != NULL)
        seen_params |= FAKE_STORE_SEEN_SERIAL;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_DIGEST) != NULL)
        seen_params |= FAKE_STORE_SEEN_DIGEST;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_FINGERPRINT) != NULL)
        seen_params |= FAKE_STORE_SEEN_FINGERPRINT;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ALIAS) != NULL)
        seen_params |= FAKE_STORE_SEEN_ALIAS;
    if (OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES) != NULL)
        seen_params |= FAKE_STORE_SEEN_PROPERTIES;
    return 1;
}

static int fake_store_load(void *loaderctx,
    OSSL_CALLBACK *object_cb, void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct fake_store_ctx_st *ctx = loaderctx;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_NAME;
    char name[16], desc[16];

    if (ctx->remaining <= 0)
        return 0;
    snprintf(name, sizeof(name), "name%d", ctx->remaining);
    snprintf(desc, sizeof(desc), "desc%d", ctx->remaining);
    ctx->remaining--;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA,
        name, 0);
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DESC,
        desc, 0);
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
}

static int fake_store_eof(void *loaderctx)
{
    struct fake_store_ctx_st *ctx = loaderctx;

    return ctx->remaining <= 0;
}

static int fake_store_close(void *loaderctx)
{
    OPENSSL_free(loaderctx);
    return 1;
}

static int fake_store_delete(void *provctx, const char *uri,
    const OSSL_PARAM params[],
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    OPENSSL_strlcpy(last_deleted, uri, sizeof(last_deleted));
    return 1;
}

static const OSSL_DISPATCH fake_store_funcs[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))fake_store_open },
    { OSSL_FUNC_STORE_ATTACH, (void (*)(void))fake_store_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
        (void (*)(void))fake_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,
        (void (*)(void))fake_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))fake_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))fake_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))fake_store_close },
    { OSSL_FUNC_STORE_DELETE, (void (*)(void))fake_store_delete },
    OSSL_DISPATCH_END
};

/* open() is required for a complete loader but open_ex() takes precedence */
static const OSSL_DISPATCH fake_store_open_ex_funcs[] = {
    { OSSL_FUNC_STORE_OPEN_EX, (void (*)(void))fake_store_open_ex },
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))fake_store_open },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
        (void (*)(void))fake_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,
        (void (*)(void))fake_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))fake_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))fake_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))fake_store_close },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM fake_store_store_algs[] = {
    { FAKE_STORE_SCHEME, FAKE_STORE_FETCH_PROPS, fake_store_funcs,
        "Fake store loader" },
    { FAKE_STORE_SCHEME_OPEN_EX, FAKE_STORE_FETCH_PROPS,
        fake_store_open_ex_funcs, "Fake store loader with open_ex" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fake_store_query(void *provctx, int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    if (operation_id == OSSL_OP_STORE)
        return fake_store_store_algs;
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fake_store_method[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fake_store_query },
    OSSL_DISPATCH_END
};

static int fake_store_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    if ((*provctx = OSSL_LIB_CTX_new()) == NULL)
        return 0;
    *out = fake_store_method;
    return 1;
}

OSSL_PROVIDER *fake_store_start(OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER *p;

    if (!OSSL_PROVIDER_add_builtin(libctx, FAKE_STORE_PROV_NAME,
            fake_store_provider_init)
        || (p = OSSL_PROVIDER_try_load(libctx, FAKE_STORE_PROV_NAME, 1)) == NULL)
        return NULL;

    return p;
}

void fake_store_finish(OSSL_PROVIDER *p)
{
    OSSL_PROVIDER_unload(p);
}
