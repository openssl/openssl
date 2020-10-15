/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/params.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn legacy_gettable_params;
static OSSL_FUNC_provider_get_params_fn legacy_get_params;
static OSSL_FUNC_provider_query_operation_fn legacy_query;

#define ALG(NAMES, FUNC) { NAMES, "provider=legacy", FUNC }

#ifdef STATIC_LEGACY
OSSL_provider_init_fn ossl_legacy_provider_init;
# define OSSL_provider_init ossl_legacy_provider_init
#endif

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM legacy_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *legacy_gettable_params(void *provctx)
{
    return legacy_param_types;
}

static int legacy_get_params(void *provctx, OSSL_PARAM params[])
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
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM legacy_digests[] = {
#ifndef OPENSSL_NO_MD2
    ALG("MD2", ossl_md2_functions),
#endif
#ifndef OPENSSL_NO_MD4
    ALG("MD4", ossl_md4_functions),
#endif
#ifndef OPENSSL_NO_MDC2
    ALG("MDC2", ossl_mdc2_functions),
#endif /* OPENSSL_NO_MDC2 */
#ifndef OPENSSL_NO_WHIRLPOOL
    ALG("WHIRLPOOL", ossl_wp_functions),
#endif /* OPENSSL_NO_WHIRLPOOL */
#ifndef OPENSSL_NO_RMD160
    ALG("RIPEMD-160:RIPEMD160:RIPEMD:RMD160", ossl_ripemd160_functions),
#endif /* OPENSSL_NO_RMD160 */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM legacy_ciphers[] = {
#ifndef OPENSSL_NO_CAST
    ALG("CAST5-ECB", ossl_cast5128ecb_functions),
    ALG("CAST5-CBC:CAST-CBC:CAST", ossl_cast5128cbc_functions),
    ALG("CAST5-OFB", ossl_cast5128ofb64_functions),
    ALG("CAST5-CFB", ossl_cast5128cfb64_functions),
#endif /* OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_BF
    ALG("BF-ECB", ossl_blowfish128ecb_functions),
    ALG("BF-CBC:BF:BLOWFISH", ossl_blowfish128cbc_functions),
    ALG("BF-OFB", ossl_blowfish64ofb64_functions),
    ALG("BF-CFB", ossl_blowfish64cfb64_functions),
#endif /* OPENSSL_NO_BF */
#ifndef OPENSSL_NO_IDEA
    ALG("IDEA-ECB", ossl_idea128ecb_functions),
    ALG("IDEA-CBC:IDEA", ossl_idea128cbc_functions),
    ALG("IDEA-OFB:IDEA-OFB64", ossl_idea128ofb64_functions),
    ALG("IDEA-CFB:IDEA-CFB64", ossl_idea128cfb64_functions),
#endif /* OPENSSL_NO_IDEA */
#ifndef OPENSSL_NO_SEED
    ALG("SEED-ECB", ossl_seed128ecb_functions),
    ALG("SEED-CBC:SEED", ossl_seed128cbc_functions),
    ALG("SEED-OFB:SEED-OFB128", ossl_seed128ofb128_functions),
    ALG("SEED-CFB:SEED-CFB128", ossl_seed128cfb128_functions),
#endif /* OPENSSL_NO_SEED */
#ifndef OPENSSL_NO_RC2
    ALG("RC2-ECB", ossl_rc2128ecb_functions),
    ALG("RC2-CBC:RC2:RC2-128", ossl_rc2128cbc_functions),
    ALG("RC2-40-CBC:RC2-40", ossl_rc240cbc_functions),
    ALG("RC2-64-CBC:RC2-64", ossl_rc264cbc_functions),
    ALG("RC2-CFB", ossl_rc2128cfb128_functions),
    ALG("RC2-OFB", ossl_rc2128ofb128_functions),
#endif /* OPENSSL_NO_RC2 */
#ifndef OPENSSL_NO_RC4
    ALG("RC4", ossl_rc4128_functions),
    ALG("RC4-40", ossl_rc440_functions),
# ifndef OPENSSL_NO_MD5
    ALG("RC4-HMAC-MD5", ossl_rc4_hmac_ossl_md5_functions),
# endif /* OPENSSL_NO_MD5 */
#endif /* OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_RC5
    ALG("RC5-ECB", ossl_rc5128ecb_functions),
    ALG("RC5-CBC:RC5", ossl_rc5128cbc_functions),
    ALG("RC5-OFB", ossl_rc5128ofb64_functions),
    ALG("RC5-CFB", ossl_rc5128cfb64_functions),
#endif /* OPENSSL_NO_RC5 */
#ifndef OPENSSL_NO_DES
    ALG("DESX-CBC:DESX", ossl_tdes_desx_cbc_functions),
    ALG("DES-ECB", ossl_des_ecb_functions),
    ALG("DES-CBC:DES", ossl_des_cbc_functions),
    ALG("DES-OFB", ossl_des_ofb64_functions),
    ALG("DES-CFB", ossl_des_cfb64_functions),
    ALG("DES-CFB1", ossl_des_cfb1_functions),
    ALG("DES-CFB8", ossl_des_cfb8_functions),
#endif /* OPENSSL_NO_DES */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *legacy_query(void *provctx, int operation_id,
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

static void legacy_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH legacy_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))legacy_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))legacy_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))legacy_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))legacy_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new()) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        legacy_teardown(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = legacy_dispatch_table;

    return 1;
}
