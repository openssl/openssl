/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/store.h>

#include "apps.h"

/*
 * Support for legacy private engine keys via the 'engine:' scheme
 *
 * engine:{engineid}:{keyid}
 *
 * Note: we ONLY support ENGINE_load_private_key() and ENGINE_load_public_key()
 * Note 2: This scheme has a precedent in code in PKIX-SSH. for exactly
 * this sort of purpose.
 */

/* Local definition of OSSL_STORE_LOADER_CTX */
struct ossl_store_loader_ctx_st {
    ENGINE *e;                   /* Structural reference */
    char *keyid;
    int privpub;                 /* 0 = load priv key, 1 = load pub key */
    int state;                   /* 0 = key not loaded yet, 1 = key loaded */
};

static OSSL_STORE_LOADER_CTX *OSSL_STORE_LOADER_CTX_new(ENGINE *e, char *keyid)
{
    OSSL_STORE_LOADER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->e = e;
        ctx->keyid = keyid;
    }
    return ctx;
}

static void OSSL_STORE_LOADER_CTX_free(OSSL_STORE_LOADER_CTX *ctx)
{
    if (ctx != NULL) {
        ENGINE_free(ctx->e);
        OPENSSL_free(ctx);
    }
}

static OSSL_STORE_LOADER_CTX *engine_open(const OSSL_STORE_LOADER *loader,
                                          const char *uri,
                                          const UI_METHOD *ui_method,
                                          void *ui_data)
{
    const char *p = uri, *q;
    ENGINE *e = NULL;
    char *keyid = NULL;
    OSSL_STORE_LOADER_CTX *ctx = NULL;

    if (strncasecmp(p, "engine:", 7) != 0)
        return NULL;
    p += 7;

    /* Look for engine ID */
    q = strchr(p, ':');
    if (q != NULL                /* There is both an engine ID and a key ID */
        && p[0] != ':'           /* The engine ID is at least one character */
        && q[1] != '\0') {       /* The key ID is at least one character */
        char engineid[256];
        size_t engineid_l = q - p;

        strncpy(engineid, p, engineid_l);
        engineid[engineid_l] = '\0';
        e = ENGINE_by_id(engineid);

        keyid = OPENSSL_strdup(q + 1);
    }

    if (e != NULL)
        ctx = OSSL_STORE_LOADER_CTX_new(e, keyid);

    return ctx;
}

static int engine_ctrl(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)
{
    int ret = 1;

    switch(cmd) {
    case APP_STORE_C_LOAD_PUBKEY:
        ctx->privpub = 1;
        break;
    case APP_STORE_C_LOAD_PRIVKEY:
        ctx->privpub = 0;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}

static OSSL_STORE_INFO *engine_load(OSSL_STORE_LOADER_CTX *ctx,
                                    const UI_METHOD *ui_method, void *ui_data)
{
    EVP_PKEY *pkey = NULL;

    if (ctx->state == 0) {
        if (ENGINE_init(ctx->e)) {
            if (ctx->privpub)
                pkey = ENGINE_load_public_key(ctx->e, ctx->keyid,
                                              (UI_METHOD *)ui_method, ui_data);
            else
                pkey = ENGINE_load_private_key(ctx->e, ctx->keyid,
                                               (UI_METHOD *)ui_method, ui_data);
            ENGINE_finish(ctx->e);
        }
    }

    ctx->state = 1;
    if (pkey == NULL)
        return NULL;

    return OSSL_STORE_INFO_new_PKEY(pkey);
}

static int engine_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    return ctx->state != 0;
}

static int engine_error(OSSL_STORE_LOADER_CTX *ctx)
{
    return 0;
}

static int engine_close(OSSL_STORE_LOADER_CTX *ctx)
{
    OSSL_STORE_LOADER_CTX_free(ctx);
    return 1;
}

int setup_engine_loader(void)
{
    OSSL_STORE_LOADER *loader = NULL;

    if ((loader = OSSL_STORE_LOADER_new(NULL, "engine")) == NULL
        || !OSSL_STORE_LOADER_set_open(loader, engine_open)
        || !OSSL_STORE_LOADER_set_ctrl(loader, engine_ctrl)
        || !OSSL_STORE_LOADER_set_load(loader, engine_load)
        || !OSSL_STORE_LOADER_set_eof(loader, engine_eof)
        || !OSSL_STORE_LOADER_set_error(loader, engine_error)
        || !OSSL_STORE_LOADER_set_close(loader, engine_close)
        || !OSSL_STORE_register_loader(loader)) {
        OSSL_STORE_LOADER_free(loader);
        loader = NULL;
    }

    return loader != NULL;
}

void destroy_engine_loader(void)
{
    OSSL_STORE_LOADER *loader = OSSL_STORE_unregister_loader("engine");
    OSSL_STORE_LOADER_free(loader);
}

