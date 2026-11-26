/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Minimal provider that creates a child library context and pulls RAND
 * into it, mirroring what e.g. the legacy provider does when an algorithm
 * implementation needs random numbers.  Used by childrand_teardown_test
 * to exercise the teardown ordering between the parent libctx's method
 * store and the child libctx's RAND thread state.
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

typedef struct {
    OSSL_LIB_CTX *libctx;
} PROV_CHILDRAND_CTX;

static void p_childrand_teardown(void *provctx)
{
    PROV_CHILDRAND_CTX *ctx = provctx;

    OSSL_LIB_CTX_free(ctx->libctx);
    OPENSSL_free(ctx);
}

static const OSSL_DISPATCH p_childrand_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_childrand_teardown },
    OSSL_DISPATCH_END
};

OSSL_provider_init_fn OSSL_provider_init; /* Check the function signature */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *oin,
    const OSSL_DISPATCH **out,
    void **provctx)
{
    PROV_CHILDRAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    unsigned char buf[16];

    if (ctx == NULL)
        return 0;
    if ((ctx->libctx = OSSL_LIB_CTX_new_child(handle, oin)) == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    /*
     * Pull RAND into the child libctx.  This instantiates the child's
     * public DRBG in the child's *thread state*, where it stays until
     * OPENSSL_thread_stop().  The DRBG is served by a child provider
     * that mirrors the parent provider's provctx, so the cipher it
     * fetches is cached in the *parent* libctx's method store, and its
     * lifetime is teardown ordering only (up_ref and free are no-ops
     * for cached methods).
     */
    if (RAND_bytes_ex(ctx->libctx, buf, sizeof(buf), 0) <= 0) {
        p_childrand_teardown(ctx);
        return 0;
    }

    *provctx = ctx;
    *out = p_childrand_dispatch_table;
    return 1;
}
