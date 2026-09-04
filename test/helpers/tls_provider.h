/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_TEST_TLS_PROVIDER_H)
#define OSSL_TEST_TLS_PROVIDER_H

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);

static ossl_inline OSSL_PROVIDER *tls_provider_load(OSSL_LIB_CTX *ctx,
    const char *name, const char *mode)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("tls-ciphersuite-mode", (char *)mode, 0),
        OSSL_PARAM_END
    };

    return OSSL_PROVIDER_load_ex(ctx, name, params);
}

/**
 * @brief Create a fresh context with the default provider and a TLS fixture.
 * @param ctx Output library context; caller must not supply a live context.
 * @param defprov Output default-provider handle.
 * @param tlsprov Output TLS-provider handle.
 * @param name Name used to register and load the built-in TLS provider.
 * @param mode Capability fixture to select.
 * @param propq Default property query, or NULL to leave defaults untouched.
 * @returns 1 on success, 0 on failure; partial outputs remain owned by caller.
 *
 * Use tls_provider_libctx_free() after freeing dependent SSL objects. Tests
 * controlling provider load timing or registering multiple fixtures do so
 * explicitly instead of using this helper.
 */
static ossl_inline int tls_provider_libctx_new(OSSL_LIB_CTX **ctx,
    OSSL_PROVIDER **defprov, OSSL_PROVIDER **tlsprov,
    const char *name, const char *mode, const char *propq)
{
    *ctx = OSSL_LIB_CTX_new();
    *defprov = NULL;
    *tlsprov = NULL;
    return *ctx != NULL
        && OSSL_PROVIDER_add_builtin(*ctx, name, tls_provider_init)
        && (*defprov = OSSL_PROVIDER_load(*ctx, "default")) != NULL
        && (*tlsprov = tls_provider_load(*ctx, name, mode)) != NULL
        && (propq == NULL || EVP_set_default_properties(*ctx, propq));
}

static ossl_inline void tls_provider_libctx_free(OSSL_LIB_CTX *ctx,
    OSSL_PROVIDER *defprov, OSSL_PROVIDER *tlsprov)
{
    OSSL_PROVIDER_unload(tlsprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(ctx);
}

#endif /* !defined(OSSL_TEST_TLS_PROVIDER_H) */
