/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h> /* NIDs used by ossl_prov_util_nid_to_name() */
#include <openssl/fips_names.h>
#include <openssl/rand_drbg.h> /* OPENSSL_CTX_get0_public_drbg() */
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/providercommonerr.h"
#include "prov/provider_util.h"
#include "self_test.h"

static const char FIPS_DEFAULT_PROPERTIES[] = "provider=fips,fips=yes";
static const char FIPS_UNAPPROVED_PROPERTIES[] = "provider=fips,fips=no";

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_teardown_fn fips_teardown;
static OSSL_FUNC_provider_gettable_params_fn fips_gettable_params;
static OSSL_FUNC_provider_get_params_fn fips_get_params;
static OSSL_FUNC_provider_query_operation_fn fips_query;

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, FIPS_DEFAULT_PROPERTIES, FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

extern OSSL_FUNC_core_thread_start_fn *c_thread_start;

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OPENSSL_CTX as a parameter.
 */

static SELF_TEST_POST_PARAMS selftest_params;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
OSSL_FUNC_core_thread_start_fn *c_thread_start;
static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;
static OSSL_FUNC_core_set_error_mark_fn *c_set_error_mark;
static OSSL_FUNC_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_FUNC_core_pop_error_to_mark_fn *c_pop_error_to_mark;
static OSSL_FUNC_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_FUNC_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_FUNC_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_FUNC_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;
static OSSL_FUNC_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_FUNC_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_FUNC_CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc;
static OSSL_FUNC_CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc;
static OSSL_FUNC_CRYPTO_secure_free_fn *c_CRYPTO_secure_free;
static OSSL_FUNC_CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free;
static OSSL_FUNC_CRYPTO_secure_allocated_fn *c_CRYPTO_secure_allocated;
static OSSL_FUNC_BIO_vsnprintf_fn *c_BIO_vsnprintf;

typedef struct fips_global_st {
    const OSSL_CORE_HANDLE *handle;
} FIPS_GLOBAL;

static void *fips_prov_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    return fgbl;
}

static void fips_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OPENSSL_CTX_METHOD fips_prov_ossl_ctx_method = {
    fips_prov_ossl_ctx_new,
    fips_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM fips_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Parameters to retrieve from the core provider - required for self testing.
 * NOTE: inside core_get_params() these will be loaded from config items
 * stored inside prov->parameters (except for
 * OSSL_PROV_PARAM_CORE_MODULE_FILENAME).
 */
static OSSL_PARAM core_params[] =
{
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
                        selftest_params.module_filename,
                        sizeof(selftest_params.module_filename)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_MODULE_MAC,
                        selftest_params.module_checksum_data,
                        sizeof(selftest_params.module_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
                        selftest_params.indicator_checksum_data,
                        sizeof(selftest_params.indicator_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                        selftest_params.indicator_data,
                        sizeof(selftest_params.indicator_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                        selftest_params.indicator_version,
                        sizeof(selftest_params.indicator_version)),
    OSSL_PARAM_END
};

static const OSSL_PARAM *fips_gettable_params(void *provctx)
{
    return fips_param_types;
}

static int fips_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL FIPS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

/* FIPS specific version of the function of the same name in provlib.c */
/* TODO(3.0) - Is this function needed ? */
const char *ossl_prov_util_nid_to_name(int nid)
{
    /* We don't have OBJ_nid2n() in FIPS_MODULE so we have an explicit list */

    switch (nid) {
    /* Digests */
    case NID_sha1:
        return "SHA1";
    case NID_sha224:
        return "SHA-224";
    case NID_sha256:
        return "SHA-256";
    case NID_sha384:
        return "SHA-384";
    case NID_sha512:
        return "SHA-512";
    case NID_sha512_224:
        return "SHA-512/224";
    case NID_sha512_256:
        return "SHA-512/256";
    case NID_sha3_224:
        return "SHA3-224";
    case NID_sha3_256:
        return "SHA3-256";
    case NID_sha3_384:
        return "SHA3-384";
    case NID_sha3_512:
        return "SHA3-512";

    /* Ciphers */
    case NID_aes_256_ecb:
        return "AES-256-ECB";
    case NID_aes_192_ecb:
        return "AES-192-ECB";
    case NID_aes_128_ecb:
        return "AES-128-ECB";
    case NID_aes_256_cbc:
        return "AES-256-CBC";
    case NID_aes_192_cbc:
        return "AES-192-CBC";
    case NID_aes_128_cbc:
        return "AES-128-CBC";
    case NID_aes_256_ctr:
        return "AES-256-CTR";
    case NID_aes_192_ctr:
        return "AES-192-CTR";
    case NID_aes_128_ctr:
        return "AES-128-CTR";
    case NID_aes_256_xts:
        return "AES-256-XTS";
    case NID_aes_128_xts:
        return "AES-128-XTS";
    case NID_aes_256_gcm:
        return "AES-256-GCM";
    case NID_aes_192_gcm:
        return "AES-192-GCM";
    case NID_aes_128_gcm:
        return "AES-128-GCM";
    case NID_aes_256_ccm:
        return "AES-256-CCM";
    case NID_aes_192_ccm:
        return "AES-192-CCM";
    case NID_aes_128_ccm:
        return "AES-128-CCM";
    case NID_id_aes256_wrap:
        return "AES-256-WRAP";
    case NID_id_aes192_wrap:
        return "AES-192-WRAP";
    case NID_id_aes128_wrap:
        return "AES-128-WRAP";
    case NID_id_aes256_wrap_pad:
        return "AES-256-WRAP-PAD";
    case NID_id_aes192_wrap_pad:
        return "AES-192-WRAP-PAD";
    case NID_id_aes128_wrap_pad:
        return "AES-128-WRAP-PAD";
    case NID_des_ede3_ecb:
        return "DES-EDE3";
    case NID_des_ede3_cbc:
        return "DES-EDE3-CBC";
    case NID_aes_256_cbc_hmac_sha256:
        return "AES-256-CBC-HMAC-SHA256";
    case NID_aes_128_cbc_hmac_sha256:
        return "AES-128-CBC-HMAC-SHA256";
    case NID_aes_256_cbc_hmac_sha1:
        return "AES-256-CBC-HMAC-SHA1";
    case NID_aes_128_cbc_hmac_sha1:
        return "AES-128-CBC-HMAC-SHA1";
    default:
        break;
    }

    return NULL;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 */
static const OSSL_ALGORITHM fips_digests[] = {
    /* Our primary name:NiST name[:our older names] */
    { "SHA1:SHA-1", FIPS_DEFAULT_PROPERTIES, sha1_functions },
    { "SHA2-224:SHA-224:SHA224", FIPS_DEFAULT_PROPERTIES, sha224_functions },
    { "SHA2-256:SHA-256:SHA256", FIPS_DEFAULT_PROPERTIES, sha256_functions },
    { "SHA2-384:SHA-384:SHA384", FIPS_DEFAULT_PROPERTIES, sha384_functions },
    { "SHA2-512:SHA-512:SHA512", FIPS_DEFAULT_PROPERTIES, sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", FIPS_DEFAULT_PROPERTIES,
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", FIPS_DEFAULT_PROPERTIES,
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", FIPS_DEFAULT_PROPERTIES, sha3_224_functions },
    { "SHA3-256", FIPS_DEFAULT_PROPERTIES, sha3_256_functions },
    { "SHA3-384", FIPS_DEFAULT_PROPERTIES, sha3_384_functions },
    { "SHA3-512", FIPS_DEFAULT_PROPERTIES, sha3_512_functions },

    { "SHAKE-128:SHAKE128", FIPS_DEFAULT_PROPERTIES, shake_128_functions },
    { "SHAKE-256:SHAKE256", FIPS_DEFAULT_PROPERTIES, shake_256_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", FIPS_DEFAULT_PROPERTIES,
      keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", FIPS_DEFAULT_PROPERTIES,
      keccak_kmac_256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE fips_ciphers[] = {
    /* Our primary name[:ASN.1 OID name][:our older names] */
    ALG("AES-256-ECB", aes256ecb_functions),
    ALG("AES-192-ECB", aes192ecb_functions),
    ALG("AES-128-ECB", aes128ecb_functions),
    ALG("AES-256-CBC", aes256cbc_functions),
    ALG("AES-192-CBC", aes192cbc_functions),
    ALG("AES-128-CBC", aes128cbc_functions),
    ALG("AES-256-CBC-CTS", aes256cbc_cts_functions),
    ALG("AES-192-CBC-CTS", aes192cbc_cts_functions),
    ALG("AES-128-CBC-CTS", aes128cbc_cts_functions),
    ALG("AES-256-OFB", aes256ofb_functions),
    ALG("AES-192-OFB", aes192ofb_functions),
    ALG("AES-128-OFB", aes128ofb_functions),
    ALG("AES-256-CFB", aes256cfb_functions),
    ALG("AES-192-CFB", aes192cfb_functions),
    ALG("AES-128-CFB", aes128cfb_functions),
    ALG("AES-256-CFB1", aes256cfb1_functions),
    ALG("AES-192-CFB1", aes192cfb1_functions),
    ALG("AES-128-CFB1", aes128cfb1_functions),
    ALG("AES-256-CFB8", aes256cfb8_functions),
    ALG("AES-192-CFB8", aes192cfb8_functions),
    ALG("AES-128-CFB8", aes128cfb8_functions),
    ALG("AES-256-CTR", aes256ctr_functions),
    ALG("AES-192-CTR", aes192ctr_functions),
    ALG("AES-128-CTR", aes128ctr_functions),
    ALG("AES-256-XTS", aes256xts_functions),
    ALG("AES-128-XTS", aes128xts_functions),
    ALG("AES-256-GCM:id-aes256-GCM", aes256gcm_functions),
    ALG("AES-192-GCM:id-aes192-GCM", aes192gcm_functions),
    ALG("AES-128-GCM:id-aes128-GCM", aes128gcm_functions),
    ALG("AES-256-CCM:id-aes256-CCM", aes256ccm_functions),
    ALG("AES-192-CCM:id-aes192-CCM", aes192ccm_functions),
    ALG("AES-128-CCM:id-aes128-CCM", aes128ccm_functions),
    ALG("AES-256-WRAP:id-aes256-wrap:AES256-WRAP", aes256wrap_functions),
    ALG("AES-192-WRAP:id-aes192-wrap:AES192-WRAP", aes192wrap_functions),
    ALG("AES-128-WRAP:id-aes128-wrap:AES128-WRAP", aes128wrap_functions),
    ALG("AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD",
        aes256wrappad_functions),
    ALG("AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD",
        aes192wrappad_functions),
    ALG("AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD",
        aes128wrappad_functions),
    ALGC("AES-128-CBC-HMAC-SHA1", aes128cbc_hmac_sha1_functions,
         cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-256-CBC-HMAC-SHA1", aes256cbc_hmac_sha1_functions,
         cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-128-CBC-HMAC-SHA256", aes128cbc_hmac_sha256_functions,
         cipher_capable_aes_cbc_hmac_sha256),
    ALGC("AES-256-CBC-HMAC-SHA256", aes256cbc_hmac_sha256_functions,
         cipher_capable_aes_cbc_hmac_sha256),
#ifndef OPENSSL_NO_DES
    ALG("DES-EDE3-ECB:DES-EDE3", tdes_ede3_ecb_functions),
    ALG("DES-EDE3-CBC:DES3", tdes_ede3_cbc_functions),
#endif  /* OPENSSL_NO_DES */
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_fips_ciphers[OSSL_NELEM(fips_ciphers)];

static const OSSL_ALGORITHM fips_macs[] = {
#ifndef OPENSSL_NO_CMAC
    { "CMAC", FIPS_DEFAULT_PROPERTIES, cmac_functions },
#endif
    { "GMAC", FIPS_DEFAULT_PROPERTIES, gmac_functions },
    { "HMAC", FIPS_DEFAULT_PROPERTIES, hmac_functions },
    { "KMAC-128:KMAC128", FIPS_DEFAULT_PROPERTIES, kmac128_functions },
    { "KMAC-256:KMAC256", FIPS_DEFAULT_PROPERTIES, kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", FIPS_DEFAULT_PROPERTIES, kdf_hkdf_functions },
    { "SSKDF", FIPS_DEFAULT_PROPERTIES, kdf_sskdf_functions },
    { "PBKDF2", FIPS_DEFAULT_PROPERTIES, kdf_pbkdf2_functions },
    { "SSHKDF", FIPS_DEFAULT_PROPERTIES, kdf_sshkdf_functions },
    { "X963KDF", FIPS_DEFAULT_PROPERTIES, kdf_x963_kdf_functions },
    { "TLS1-PRF", FIPS_DEFAULT_PROPERTIES, kdf_tls1_prf_functions },
    { "KBKDF", FIPS_DEFAULT_PROPERTIES, kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_rands[] = {
    { "CTR-DRBG", FIPS_DEFAULT_PROPERTIES, drbg_ctr_functions },
    { "HASH-DRBG", FIPS_DEFAULT_PROPERTIES, drbg_hash_functions },
    { "HMAC-DRBG", FIPS_DEFAULT_PROPERTIES, drbg_hmac_functions },
    { "TEST-RAND", FIPS_UNAPPROVED_PROPERTIES, test_rng_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", FIPS_DEFAULT_PROPERTIES, dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { "ECDH", FIPS_DEFAULT_PROPERTIES, ecdh_keyexch_functions },
    { "X25519", FIPS_DEFAULT_PROPERTIES, x25519_keyexch_functions },
    { "X448", FIPS_DEFAULT_PROPERTIES, x448_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", FIPS_DEFAULT_PROPERTIES, dsa_signature_functions },
#endif
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES, rsa_signature_functions },
#ifndef OPENSSL_NO_EC
    { "ED25519", FIPS_DEFAULT_PROPERTIES, ed25519_signature_functions },
    { "ED448", FIPS_DEFAULT_PROPERTIES, ed448_signature_functions },
    { "ECDSA", FIPS_DEFAULT_PROPERTIES, ecdsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_asym_cipher[] = {
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES, rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", FIPS_DEFAULT_PROPERTIES, dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA", FIPS_DEFAULT_PROPERTIES, dsa_keymgmt_functions },
#endif
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES, rsa_keymgmt_functions },
    { "RSA-PSS:RSASSA-PSS", FIPS_DEFAULT_PROPERTIES,
      rsapss_keymgmt_functions },
#ifndef OPENSSL_NO_EC
    { "EC:id-ecPublicKey", FIPS_DEFAULT_PROPERTIES, ec_keymgmt_functions },
    { "X25519", FIPS_DEFAULT_PROPERTIES, x25519_keymgmt_functions },
    { "X448", FIPS_DEFAULT_PROPERTIES, x448_keymgmt_functions },
    { "ED25519", FIPS_DEFAULT_PROPERTIES, ed25519_keymgmt_functions },
    { "ED448", FIPS_DEFAULT_PROPERTIES, ed448_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(void *provctx, int operation_id,
                                        int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    case OSSL_OP_CIPHER:
        ossl_prov_cache_exported_algorithms(fips_ciphers, exported_fips_ciphers);
        return exported_fips_ciphers;
    case OSSL_OP_MAC:
        return fips_macs;
    case OSSL_OP_KDF:
        return fips_kdfs;
    case OSSL_OP_RAND:
        return fips_rands;
    case OSSL_OP_KEYMGMT:
        return fips_keymgmt;
    case OSSL_OP_KEYEXCH:
        return fips_keyexch;
    case OSSL_OP_SIGNATURE:
        return fips_signature;
    case OSSL_OP_ASYM_CIPHER:
        return fips_asym_cipher;
    }
    return NULL;
}

static void fips_teardown(void *provctx)
{
    OPENSSL_CTX_free(PROV_LIBRARY_CONTEXT_OF(provctx));
    PROV_CTX_free(provctx);
}

static void fips_intern_teardown(void *provctx)
{
    /*
     * We know that the library context is the same as for the outer provider,
     * so no need to destroy it here.
     */
    PROV_CTX_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))fips_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fips_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))provider_get_capabilities },
    { 0, NULL }
};

/* Functions we provide to ourself */
static const OSSL_DISPATCH intern_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))fips_intern_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    FIPS_GLOBAL *fgbl;
    OPENSSL_CTX *libctx = NULL;
    OSSL_FUNC_self_test_cb_fn *stcbfn = NULL;
    OSSL_FUNC_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_FUNC_core_get_library_context(in);
            break;
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_FUNC_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            c_set_error_mark = OSSL_FUNC_core_set_error_mark(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            c_clear_last_error_mark = OSSL_FUNC_core_clear_last_error_mark(in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            c_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_CRYPTO_malloc = OSSL_FUNC_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_CRYPTO_zalloc = OSSL_FUNC_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_CRYPTO_free = OSSL_FUNC_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            c_CRYPTO_clear_free = OSSL_FUNC_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            c_CRYPTO_realloc = OSSL_FUNC_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            c_CRYPTO_clear_realloc = OSSL_FUNC_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            c_CRYPTO_secure_malloc = OSSL_FUNC_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            c_CRYPTO_secure_zalloc = OSSL_FUNC_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            c_CRYPTO_secure_free = OSSL_FUNC_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            c_CRYPTO_secure_clear_free = OSSL_FUNC_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            c_CRYPTO_secure_allocated = OSSL_FUNC_CRYPTO_secure_allocated(in);
            break;
        case OSSL_FUNC_BIO_NEW_FILE:
            selftest_params.bio_new_file_cb = OSSL_FUNC_BIO_new_file(in);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            selftest_params.bio_new_buffer_cb = OSSL_FUNC_BIO_new_membuf(in);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            selftest_params.bio_read_ex_cb = OSSL_FUNC_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_FREE:
            selftest_params.bio_free_cb = OSSL_FUNC_BIO_free(in);
            break;
        case OSSL_FUNC_BIO_VSNPRINTF:
            c_BIO_vsnprintf = OSSL_FUNC_BIO_vsnprintf(in);
            break;
        case OSSL_FUNC_SELF_TEST_CB: {
            stcbfn = OSSL_FUNC_self_test_cb(in);
            break;
        }
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (stcbfn != NULL && c_get_libctx != NULL) {
        stcbfn(c_get_libctx(handle), &selftest_params.cb,
               &selftest_params.cb_arg);
    }
    else {
        selftest_params.cb = NULL;
        selftest_params.cb_arg = NULL;
    }

    if (!c_get_params(handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    /*  Create a context. */
    if ((*provctx = PROV_CTX_new()) == NULL
        || (libctx = OPENSSL_CTX_new()) == NULL) {
        /*
         * We free libctx separately here and only here because it hasn't
         * been attached to *provctx.  All other error paths below rely
         * solely on fips_teardown.
         */
        OPENSSL_CTX_free(libctx);
        goto err;
    }
    PROV_CTX_set0_library_context(*provctx, libctx);
    PROV_CTX_set0_handle(*provctx, handle);

    if ((fgbl = openssl_ctx_get_data(libctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                     &fips_prov_ossl_ctx_method)) == NULL)
        goto err;

    fgbl->handle = handle;

    selftest_params.libctx = libctx;
    if (!SELF_TEST_post(&selftest_params, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
        goto err;
    }

    /* TODO(3.0): Tests will hang if this is removed */
    (void)OPENSSL_CTX_get0_public_drbg(libctx);

    *out = fips_dispatch_table;
    return 1;
 err:
    fips_teardown(*provctx);
    *provctx = NULL;
    return 0;
}

/*
 * The internal init function used when the FIPS module uses EVP to call
 * another algorithm also in the FIPS module. This is a recursive call that has
 * been made from within the FIPS module itself. To make this work, we populate
 * the provider context of this inner instance with the same library context
 * that was used in the EVP call that initiated this recursive call.
 */
OSSL_provider_init_fn fips_intern_provider_init;
int fips_intern_provider_init(const OSSL_CORE_HANDLE *handle,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    OSSL_FUNC_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_FUNC_core_get_library_context(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    if ((*provctx = PROV_CTX_new()) == NULL)
        return 0;
    /*
     * Using the parent library context only works because we are a built-in
     * internal provider. This is not something that most providers would be
     * able to do.
     */
    PROV_CTX_set0_library_context(*provctx, (OPENSSL_CTX *)c_get_libctx(handle));
    PROV_CTX_set0_handle(*provctx, handle);

    *out = intern_dispatch_table;
    return 1;
}

void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

int ERR_set_mark(void)
{
    return c_set_error_mark(NULL);
}

int ERR_clear_last_mark(void)
{
    return c_clear_last_error_mark(NULL);
}

int ERR_pop_to_mark(void)
{
    return c_pop_error_to_mark(NULL);
}

/*
 * This must take a library context, since it's called from the depths
 * of crypto/initthread.c code, where it's (correctly) assumed that the
 * passed caller argument is an OPENSSL_CTX pointer (since the same routine
 * is also called from other parts of libcrypto, which all pass around a
 * OPENSSL_CTX pointer)
 */
const OSSL_CORE_HANDLE *FIPS_get_core_handle(OPENSSL_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = openssl_ctx_get_data(libctx,
                                             OPENSSL_CTX_FIPS_PROV_INDEX,
                                             &fips_prov_ossl_ctx_method);

    if (fgbl == NULL)
        return NULL;

    return fgbl->handle;
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_malloc(num, file, line);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_zalloc(num, file, line);
}

void CRYPTO_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_free(ptr, file, line);
}

void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_clear_free(ptr, num, file, line);
}

void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)
{
    return c_CRYPTO_realloc(addr, num, file, line);
}

void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line)
{
    return c_CRYPTO_clear_realloc(addr, old_num, num, file, line);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_malloc(num, file, line);
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_zalloc(num, file, line);
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_secure_free(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_secure_clear_free(ptr, num, file, line);
}

int CRYPTO_secure_allocated(const void *ptr)
{
    return c_CRYPTO_secure_allocated(ptr);
}

int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = c_BIO_vsnprintf(buf, n, format, args);
    va_end(args);
    return ret;
}
