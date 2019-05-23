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
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/provider_algs.h"

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM deflt_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *deflt_gettable_params(const OSSL_PROVIDER *prov)
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
    { sha1_names, "default=yes", sha1_functions },

    { sha224_names, "default=yes", sha224_functions },
    { sha256_names, "default=yes", sha256_functions },
    { sha384_names, "default=yes", sha384_functions },
    { sha512_names, "default=yes", sha512_functions },
    { sha512_224_names, "default=yes", sha512_224_functions },
    { sha512_256_names, "default=yes", sha512_256_functions },

    { sha3_224_names, "default=yes", sha3_224_functions },
    { sha3_256_names, "default=yes", sha3_256_functions },
    { sha3_384_names, "default=yes", sha3_384_functions },
    { sha3_512_names, "default=yes", sha3_512_functions },

    { keccak_kmac_128_names, "default=yes", keccak_kmac_128_functions },
    { keccak_kmac_256_names, "default=yes", keccak_kmac_256_functions },

    { shake_128_names, "default=yes", shake_128_functions },
    { shake_256_names, "default=yes", shake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    { blake2s256_names, "default=yes", blake2s256_functions },
    { blake2b512_names, "default=yes", blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { sm3_names, "default=yes", sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { md5_names, "default=yes", md5_functions },
    { md5_sha1_names, "default=yes", md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_ciphers[] = {
    { aes256ecb_names, "default=yes", aes256ecb_functions },
    { aes192ecb_names, "default=yes", aes192ecb_functions },
    { aes128ecb_names, "default=yes", aes128ecb_functions },
    { aes256cbc_names, "default=yes", aes256cbc_functions },
    { aes192cbc_names, "default=yes", aes192cbc_functions },
    { aes128cbc_names, "default=yes", aes128cbc_functions },
    { aes256ofb_names, "default=yes", aes256ofb_functions },
    { aes192ofb_names, "default=yes", aes192ofb_functions },
    { aes128ofb_names, "default=yes", aes128ofb_functions },
    { aes256cfb_names, "default=yes", aes256cfb_functions },
    { aes192cfb_names, "default=yes", aes192cfb_functions },
    { aes128cfb_names, "default=yes", aes128cfb_functions },
    { aes256cfb1_names, "default=yes", aes256cfb1_functions },
    { aes192cfb1_names, "default=yes", aes192cfb1_functions },
    { aes128cfb1_names, "default=yes", aes128cfb1_functions },
    { aes256cfb8_names, "default=yes", aes256cfb8_functions },
    { aes192cfb8_names, "default=yes", aes192cfb8_functions },
    { aes128cfb8_names, "default=yes", aes128cfb8_functions },
    { aes256ctr_names, "default=yes", aes256ctr_functions },
    { aes192ctr_names, "default=yes", aes192ctr_functions },
    { aes128ctr_names, "default=yes", aes128ctr_functions },
    { aes256xts_names, "default=yes", aes256xts_functions },
    { aes128xts_names, "default=yes", aes128xts_functions },
#ifndef OPENSSL_NO_OCB
    { aes256ocb_names, "default=yes", aes256ocb_functions },
    { aes192ocb_names, "default=yes", aes192ocb_functions },
    { aes128ocb_names, "default=yes", aes128ocb_functions },
#endif /* OPENSSL_NO_OCB */
    { aes256gcm_names, "default=yes", aes256gcm_functions },
    { aes192gcm_names, "default=yes", aes192gcm_functions },
    { aes128gcm_names, "default=yes", aes128gcm_functions },
    { aes256ccm_names, "default=yes", aes256ccm_functions },
    { aes192ccm_names, "default=yes", aes192ccm_functions },
    { aes128ccm_names, "default=yes", aes128ccm_functions },
    { aes256wrap_names, "default=yes", aes256wrap_functions },
    { aes192wrap_names, "default=yes", aes192wrap_functions },
    { aes128wrap_names, "default=yes", aes128wrap_functions },
    { aes256wrappad_names, "default=yes", aes256wrappad_functions },
    { aes192wrappad_names, "default=yes", aes192wrappad_functions },
    { aes128wrappad_names, "default=yes", aes128wrappad_functions },
#ifndef OPENSSL_NO_ARIA
    { aria256gcm_names, "default=yes", aria256gcm_functions },
    { aria192gcm_names, "default=yes", aria192gcm_functions },
    { aria128gcm_names, "default=yes", aria128gcm_functions },
    { aria256ccm_names, "default=yes", aria256ccm_functions },
    { aria192ccm_names, "default=yes", aria192ccm_functions },
    { aria128ccm_names, "default=yes", aria128ccm_functions },
    { aria256ecb_names, "default=yes", aria256ecb_functions },
    { aria192ecb_names, "default=yes", aria192ecb_functions },
    { aria128ecb_names, "default=yes", aria128ecb_functions },
    { aria256cbc_names, "default=yes", aria256cbc_functions },
    { aria192cbc_names, "default=yes", aria192cbc_functions },
    { aria128cbc_names, "default=yes", aria128cbc_functions },
    { aria256ofb_names, "default=yes", aria256ofb_functions },
    { aria192ofb_names, "default=yes", aria192ofb_functions },
    { aria128ofb_names, "default=yes", aria128ofb_functions },
    { aria256cfb_names, "default=yes", aria256cfb_functions },
    { aria192cfb_names, "default=yes", aria192cfb_functions },
    { aria128cfb_names, "default=yes", aria128cfb_functions },
    { aria256cfb1_names, "default=yes", aria256cfb1_functions },
    { aria192cfb1_names, "default=yes", aria192cfb1_functions },
    { aria128cfb1_names, "default=yes", aria128cfb1_functions },
    { aria256cfb8_names, "default=yes", aria256cfb8_functions },
    { aria192cfb8_names, "default=yes", aria192cfb8_functions },
    { aria128cfb8_names, "default=yes", aria128cfb8_functions },
    { aria256ctr_names, "default=yes", aria256ctr_functions },
    { aria192ctr_names, "default=yes", aria192ctr_functions },
    { aria128ctr_names, "default=yes", aria128ctr_functions },
#endif /* OPENSSL_NO_ARIA */
#ifndef OPENSSL_NO_CAMELLIA
    { camellia256ecb_names, "default=yes", camellia256ecb_functions },
    { camellia192ecb_names, "default=yes", camellia192ecb_functions },
    { camellia128ecb_names, "default=yes", camellia128ecb_functions },
    { camellia256cbc_names, "default=yes", camellia256cbc_functions },
    { camellia192cbc_names, "default=yes", camellia192cbc_functions },
    { camellia128cbc_names, "default=yes", camellia128cbc_functions },
    { camellia256ofb_names, "default=yes", camellia256ofb_functions },
    { camellia192ofb_names, "default=yes", camellia192ofb_functions },
    { camellia128ofb_names, "default=yes", camellia128ofb_functions },
    { camellia256cfb_names, "default=yes", camellia256cfb_functions },
    { camellia192cfb_names, "default=yes", camellia192cfb_functions },
    { camellia128cfb_names, "default=yes", camellia128cfb_functions },
    { camellia256cfb1_names, "default=yes", camellia256cfb1_functions },
    { camellia192cfb1_names, "default=yes", camellia192cfb1_functions },
    { camellia128cfb1_names, "default=yes", camellia128cfb1_functions },
    { camellia256cfb8_names, "default=yes", camellia256cfb8_functions },
    { camellia192cfb8_names, "default=yes", camellia192cfb8_functions },
    { camellia128cfb8_names, "default=yes", camellia128cfb8_functions },
    { camellia256ctr_names, "default=yes", camellia256ctr_functions },
    { camellia192ctr_names, "default=yes", camellia192ctr_functions },
    { camellia128ctr_names, "default=yes", camellia128ctr_functions },
#endif /* OPENSSL_NO_CAMELLIA */
#ifndef OPENSSL_NO_DES
    { tdes_ede3_ecb_names, "default=yes", tdes_ede3_ecb_functions },
    { tdes_ede3_cbc_names, "default=yes", tdes_ede3_cbc_functions },
    { tdes_ede3_ofb_names, "default=yes", tdes_ede3_ofb_functions },
    { tdes_ede3_cfb_names, "default=yes", tdes_ede3_cfb_functions },
    { tdes_ede3_cfb8_names, "default=yes", tdes_ede3_cfb8_functions },
    { tdes_ede3_cfb1_names, "default=yes", tdes_ede3_cfb1_functions },
    { tdes_ede2_ecb_names, "default=yes", tdes_ede2_ecb_functions },
    { tdes_ede2_cbc_names, "default=yes", tdes_ede2_cbc_functions },
    { tdes_ede2_ofb_names, "default=yes", tdes_ede2_ofb_functions },
    { tdes_ede2_cfb_names, "default=yes", tdes_ede2_cfb_functions },
    { tdes_desx_cbc_names, "default=yes", tdes_desx_cbc_functions },
    { tdes_wrap_cbc_names, "default=yes", tdes_wrap_cbc_functions },
    { des_ecb_names, "default=yes", des_ecb_functions },
    { des_cbc_names, "default=yes", des_cbc_functions },
    { des_ofb64_names, "default=yes", des_ofb64_functions },
    { des_cfb64_names, "default=yes", des_cfb64_functions },
    { des_cfb1_names, "default=yes", des_cfb1_functions },
    { des_cfb8_names, "default=yes", des_cfb8_functions },
#endif /* OPENSSL_NO_DES */
#ifndef OPENSSL_NO_BF
    { blowfish128ecb_names, "default=yes", blowfish128ecb_functions },
    { blowfish128cbc_names, "default=yes", blowfish128cbc_functions },
    { blowfish64ofb64_names, "default=yes", blowfish64ofb64_functions },
    { blowfish64cfb64_names, "default=yes", blowfish64cfb64_functions },
#endif /* OPENSSL_NO_BF */
#ifndef OPENSSL_NO_IDEA
    { idea128ecb_names, "default=yes", idea128ecb_functions },
    { idea128cbc_names, "default=yes", idea128cbc_functions },
    { idea128ofb64_names, "default=yes", idea128ofb64_functions },
    { idea128cfb64_names, "default=yes", idea128cfb64_functions },
#endif /* OPENSSL_NO_IDEA */
#ifndef OPENSSL_NO_CAST
    { cast5128ecb_names, "default=yes", cast5128ecb_functions },
    { cast5128cbc_names, "default=yes", cast5128cbc_functions },
    { cast564ofb64_names, "default=yes", cast564ofb64_functions },
    { cast564cfb64_names, "default=yes", cast564cfb64_functions },
#endif /* OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_SEED
    { seed128ecb_names, "default=yes", seed128ecb_functions },
    { seed128cbc_names, "default=yes", seed128cbc_functions },
    { seed128ofb128_names, "default=yes", seed128ofb128_functions },
    { seed128cfb128_names, "default=yes", seed128cfb128_functions },
#endif /* OPENSSL_NO_SEED */
#ifndef OPENSSL_NO_SM4
    { sm4128ecb_names, "default=yes", sm4128ecb_functions },
    { sm4128cbc_names, "default=yes", sm4128cbc_functions },
    { sm4128ctr_names, "default=yes", sm4128ctr_functions },
    { sm4128ofb128_names, "default=yes", sm4128ofb128_functions },
    { sm4128cfb128_names, "default=yes", sm4128cfb128_functions },
#endif /* OPENSSL_NO_SM4 */
#ifndef OPENSSL_NO_RC4
    { "RC4", "default=yes", rc4128_functions },
    { "RC4-40", "default=yes", rc440_functions },
#endif /* OPENSSL_NO_RC4 */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_macs[] = {
#ifndef OPENSSL_NO_BLAKE2
    { blake2bmac_names, "default=yes", blake2bmac_functions },
    { blake2smac_names, "default=yes", blake2smac_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { cmac_names, "default=yes", cmac_functions },
#endif
    { gmac_names, "default=yes", gmac_functions },
    { hmac_names, "default=yes", hmac_functions },
    { kmac128_names, "default=yes", kmac128_functions },
    { kmac256_names, "default=yes", kmac256_functions },
#ifndef OPENSSL_NO_SIPHASH
    { siphash_names, "default=yes", siphash_functions },
#endif
#ifndef OPENSSL_NO_POLY1305
    { poly1305_names, "default=yes", poly1305_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_kdfs[] = {
    { kdf_hkdf_names, "default=yes", kdf_hkdf_functions },
    { kdf_sskdf_names, "default=yes", kdf_sskdf_functions },
    { kdf_pbkdf2_names, "default=yes", kdf_pbkdf2_functions },
    { kdf_sshkdf_names, "default=yes", kdf_sshkdf_functions },
    { kdf_x963_kdf_names, "default=yes", kdf_x963_kdf_functions },
    { kdf_tls1_prf_names, "default=yes", kdf_tls1_prf_functions },
    { kdf_kbkdf_names, "default=yes", kdf_kbkdf_functions },
#ifndef OPENSSL_NO_CMS
    { kdf_x942_kdf_names, "default=yes", kdf_x942_kdf_functions },
#endif
#ifndef OPENSSL_NO_SCRYPT
    { kdf_scrypt_names, "default=yes", kdf_scrypt_functions },
#endif
   { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { dh_names, "default=yes", dh_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_signature[] = {
#ifndef OPENSSL_NO_DSA
    { dsa_names, "default=yes", dsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};


static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { dh_names, "default=yes", dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { dsa_names, "default=yes", dsa_keymgmt_functions },
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
    case OSSL_OP_MAC:
        return deflt_macs;
    case OSSL_OP_KDF:
        return deflt_kdfs;
    case OSSL_OP_KEYMGMT:
        return deflt_keymgmt;
    case OSSL_OP_KEYEXCH:
        return deflt_keyexch;
    case OSSL_OP_SIGNATURE:
        return deflt_signature;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))deflt_gettable_params },
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
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
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
