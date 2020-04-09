/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/implementations.h"

#define ALG(NAMES, FUNC) { NAMES, "provider=legacy", FUNC }

#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_ITEM legacy_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const OSSL_ITEM *legacy_gettable_params(const OSSL_PROVIDER *prov)
{
    return legacy_param_types;
}

static int legacy_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Legacy Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM legacy_digests[] = {
#ifndef OPENSSL_NO_MD2
    ALG("MD2", md2_functions),
#endif
#ifndef OPENSSL_NO_MD4
    ALG("MD4", md4_functions),
#endif
#ifndef OPENSSL_NO_MDC2
    ALG("MDC2", mdc2_functions),
#endif /* OPENSSL_NO_MDC2 */
#ifndef OPENSSL_NO_WHIRLPOOL
    ALG("WHIRLPOOL", wp_functions),
#endif /* OPENSSL_NO_WHIRLPOOL */
#ifndef OPENSSL_NO_RMD160
    ALG("RIPEMD-160:RIPEMD160:RIPEMD:RMD160", ripemd160_functions),
#endif /* OPENSSL_NO_RMD160 */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM legacy_ciphers[] = {
#ifndef OPENSSL_NO_CAST
    ALG("CAST5-ECB", cast5128ecb_functions),
    ALG("CAST5-CBC:CAST-CBC:CAST", cast5128cbc_functions),
    ALG("CAST5-OFB", cast564ofb64_functions),
    ALG("CAST5-CFB", cast564cfb64_functions),
#endif /* OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_BF
    ALG("BF-ECB", blowfish128ecb_functions),
    ALG("BF-CBC:BF:BLOWFISH", blowfish128cbc_functions),
    ALG("BF-OFB", blowfish64ofb64_functions),
    ALG("BF-CFB", blowfish64cfb64_functions),
#endif /* OPENSSL_NO_BF */
#ifndef OPENSSL_NO_IDEA
    ALG("IDEA-ECB", idea128ecb_functions),
    ALG("IDEA-CBC:IDEA", idea128cbc_functions),
    ALG("IDEA-OFB:IDEA-OFB64", idea128ofb64_functions),
    ALG("IDEA-CFB:IDEA-CFB64", idea128cfb64_functions),
#endif /* OPENSSL_NO_IDEA */
#ifndef OPENSSL_NO_SEED
    ALG("SEED-ECB", seed128ecb_functions),
    ALG("SEED-CBC:SEED", seed128cbc_functions),
    ALG("SEED-OFB:SEED-OFB128", seed128ofb128_functions),
    ALG("SEED-CFB:SEED-CFB128", seed128cfb128_functions),
#endif /* OPENSSL_NO_SEED */
#ifndef OPENSSL_NO_RC2
    ALG("RC2-ECB", rc2128ecb_functions),
    ALG("RC2-CBC", rc2128cbc_functions),
    ALG("RC2-40-CBC", rc240cbc_functions),
    ALG("RC2-64-CBC", rc264cbc_functions),
    ALG("RC2-CFB", rc2128cfb128_functions),
    ALG("RC2-OFB", rc2128ofb128_functions),
#endif /* OPENSSL_NO_RC2 */
#ifndef OPENSSL_NO_RC4
    ALG("RC4", rc4128_functions),
    ALG("RC4-40", rc440_functions),
# ifndef OPENSSL_NO_MD5
    ALG("RC4-HMAC-MD5", rc4_hmac_md5_functions),
# endif /* OPENSSL_NO_MD5 */
#endif /* OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_RC5
    ALG("RC5-ECB", rc5128ecb_functions),
    ALG("RC5-CBC", rc5128cbc_functions),
    ALG("RC5-OFB", rc5128ofb64_functions),
    ALG("RC5-CFB", rc5128cfb64_functions),
#endif /* OPENSSL_NO_RC5 */
#ifndef OPENSSL_NO_DES
    ALG("DESX-CBC:DESX", tdes_desx_cbc_functions),
    ALG("DES-ECB", des_ecb_functions),
    ALG("DES-CBC:DES", des_cbc_functions),
    ALG("DES-OFB", des_ofb64_functions),
    ALG("DES-CFB", des_cfb64_functions),
    ALG("DES-CFB1", des_cfb1_functions),
    ALG("DES-CFB8", des_cfb8_functions),
#endif /* OPENSSL_NO_DES */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *legacy_query(OSSL_PROVIDER *prov,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return legacy_digests;
    case OSSL_OP_CIPHER:
        return legacy_ciphers;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH legacy_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))legacy_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))legacy_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))legacy_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *out = legacy_dispatch_table;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along as the provider context.
     */
    *provctx = c_get_libctx(provider);
    return 1;
}
