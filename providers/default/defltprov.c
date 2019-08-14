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
#include "internal/provider_algs.h"

/* Functions provided by the core */
static OSSL_core_gettable_types_fn *c_gettable_types = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM deflt_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *deflt_gettable_types(const OSSL_PROVIDER *prov)
{
    return deflt_param_types;
}

static int deflt_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Default Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM deflt_digests[] = {
    { "SHA1", "default=yes", sha1_functions },

    { "SHA224", "default=yes", sha224_functions },
    { "SHA256", "default=yes", sha256_functions },
    { "SHA384", "default=yes", sha384_functions },
    { "SHA512", "default=yes", sha512_functions },
    { "SHA512-224", "default=yes", sha512_224_functions },
    { "SHA512-256", "default=yes", sha512_256_functions },

    { "SHA3-224", "default=yes", sha3_224_functions },
    { "SHA3-256", "default=yes", sha3_256_functions },
    { "SHA3-384", "default=yes", sha3_384_functions },
    { "SHA3-512", "default=yes", sha3_512_functions },

    { "KMAC128", "default=yes", keccak_kmac_128_functions },
    { "KMAC256", "default=yes", keccak_kmac_256_functions },

    { "SHAKE128", "default=yes", shake_128_functions },
    { "SHAKE256", "default=yes", shake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    { "BLAKE2s256", "default=yes", blake2s256_functions },
    { "BLAKE2b512", "default=yes", blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { "SM3", "default=yes", sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { "MD5", "default=yes", md5_functions },
    { "MD5-SHA1", "default=yes", md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

    /*{ "UNDEF", "default=yes", nullmd_functions }, */

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_ciphers[] = {
    { "AES-256-ECB", "default=yes", aes256ecb_functions },
    { "AES-192-ECB", "default=yes", aes192ecb_functions },
    { "AES-128-ECB", "default=yes", aes128ecb_functions },
    { "AES-256-CBC", "default=yes", aes256cbc_functions },
    { "AES-192-CBC", "default=yes", aes192cbc_functions },
    { "AES-128-CBC", "default=yes", aes128cbc_functions },
    { "AES-256-OFB", "default=yes", aes256ofb_functions },
    { "AES-192-OFB", "default=yes", aes192ofb_functions },
    { "AES-128-OFB", "default=yes", aes128ofb_functions },
    { "AES-256-CFB", "default=yes", aes256cfb_functions },
    { "AES-192-CFB", "default=yes", aes192cfb_functions },
    { "AES-128-CFB", "default=yes", aes128cfb_functions },
    { "AES-256-CFB1", "default=yes", aes256cfb1_functions },
    { "AES-192-CFB1", "default=yes", aes192cfb1_functions },
    { "AES-128-CFB1", "default=yes", aes128cfb1_functions },
    { "AES-256-CFB8", "default=yes", aes256cfb8_functions },
    { "AES-192-CFB8", "default=yes", aes192cfb8_functions },
    { "AES-128-CFB8", "default=yes", aes128cfb8_functions },
    { "AES-256-CTR", "default=yes", aes256ctr_functions },
    { "AES-192-CTR", "default=yes", aes192ctr_functions },
    { "AES-128-CTR", "default=yes", aes128ctr_functions },
    { "id-aes256-GCM", "default=yes", aes256gcm_functions },
    { "id-aes192-GCM", "default=yes", aes192gcm_functions },
    { "id-aes128-GCM", "default=yes", aes128gcm_functions },
#ifndef OPENSSL_NO_ARIA
    { "ARIA-256-GCM", "default=yes", aria256gcm_functions },
    { "ARIA-192-GCM", "default=yes", aria192gcm_functions },
    { "ARIA-128-GCM", "default=yes", aria128gcm_functions },
#endif /* OPENSSL_NO_ARIA */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "dhKeyAgreement", "default=yes", dh_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "dhKeyAgreement", "default=yes", dh_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *deflt_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return deflt_digests;
    case OSSL_OP_CIPHER:
        return deflt_ciphers;
    case OSSL_OP_KEYMGMT:
        return deflt_keymgmt;
    case OSSL_OP_KEYEXCH:
        return deflt_keyexch;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_TYPES, (void (*)(void))deflt_gettable_types },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))deflt_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))deflt_query },
    { 0, NULL }
};

OSSL_provider_init_fn ossl_default_provider_init;

int ossl_default_provider_init(const OSSL_PROVIDER *provider,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_TYPES:
            c_gettable_types = OSSL_get_core_gettable_types(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *out = deflt_dispatch_table;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along as the provider context.
     */
    *provctx = c_get_libctx(provider);
    return 1;
}
