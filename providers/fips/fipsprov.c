/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/fips_names.h>
#include <openssl/rand.h> /* RAND_get0_public() */
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/providercommonerr.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
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
int FIPS_security_check_enabled(void);

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OSSL_LIB_CTX as a parameter.
 */

static SELF_TEST_POST_PARAMS selftest_params;
static int fips_security_checks = 1;
static const char *fips_security_check_option = "1";

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
static OSSL_FUNC_self_test_cb_fn *c_stcbfn = NULL;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

typedef struct fips_global_st {
    const OSSL_CORE_HANDLE *handle;
} FIPS_GLOBAL;

static void *fips_prov_ossl_ctx_new(OSSL_LIB_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    return fgbl;
}

static void fips_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OSSL_LIB_CTX_METHOD fips_prov_ossl_ctx_method = {
    fips_prov_ossl_ctx_new,
    fips_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM fips_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_SECURITY_CHECKS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Parameters to retrieve from the core provider - required for self testing.
 * NOTE: inside core_get_params() these will be loaded from config items
 * stored inside prov->parameters (except for
 * OSSL_PROV_PARAM_CORE_MODULE_FILENAME).
 * OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS is not a self test parameter.
 */
static OSSL_PARAM core_params[] =
{
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
                        &selftest_params.module_filename,
                        sizeof(selftest_params.module_filename)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_MODULE_MAC,
                        &selftest_params.module_checksum_data,
                        sizeof(selftest_params.module_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
                        &selftest_params.indicator_checksum_data,
                        sizeof(selftest_params.indicator_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                        &selftest_params.indicator_data,
                        sizeof(selftest_params.indicator_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                        &selftest_params.indicator_version,
                        sizeof(selftest_params.indicator_version)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
                        &selftest_params.conditional_error_check,
                        sizeof(selftest_params.conditional_error_check)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS,
                        &fips_security_check_option,
                        sizeof(fips_security_check_option)),
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
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_SECURITY_CHECKS);
    if (p != NULL && !OSSL_PARAM_set_int(p, fips_security_checks))
        return 0;
    return 1;
}

static void set_self_test_cb(const OSSL_CORE_HANDLE *handle)
{
    if (c_stcbfn != NULL && c_get_libctx != NULL) {
        c_stcbfn(c_get_libctx(handle), &selftest_params.cb,
                              &selftest_params.cb_arg);
    } else {
        selftest_params.cb = NULL;
        selftest_params.cb_arg = NULL;
    }
}

static int fips_self_test(void *provctx)
{
    set_self_test_cb(FIPS_get_core_handle(selftest_params.libctx));
    return SELF_TEST_post(&selftest_params, 1) ? 1 : 0;
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
    { "SHA1:SHA-1:SSL3-SHA1", FIPS_DEFAULT_PROPERTIES, ossl_sha1_functions },
    { "SHA2-224:SHA-224:SHA224", FIPS_DEFAULT_PROPERTIES,
      ossl_sha224_functions },
    { "SHA2-256:SHA-256:SHA256", FIPS_DEFAULT_PROPERTIES,
      ossl_sha256_functions },
    { "SHA2-384:SHA-384:SHA384", FIPS_DEFAULT_PROPERTIES,
      ossl_sha384_functions },
    { "SHA2-512:SHA-512:SHA512", FIPS_DEFAULT_PROPERTIES,
      ossl_sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", FIPS_DEFAULT_PROPERTIES,
      ossl_sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", FIPS_DEFAULT_PROPERTIES,
      ossl_sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", FIPS_DEFAULT_PROPERTIES, ossl_sha3_224_functions },
    { "SHA3-256", FIPS_DEFAULT_PROPERTIES, ossl_sha3_256_functions },
    { "SHA3-384", FIPS_DEFAULT_PROPERTIES, ossl_sha3_384_functions },
    { "SHA3-512", FIPS_DEFAULT_PROPERTIES, ossl_sha3_512_functions },

    { "SHAKE-128:SHAKE128", FIPS_DEFAULT_PROPERTIES, ossl_shake_128_functions },
    { "SHAKE-256:SHAKE256", FIPS_DEFAULT_PROPERTIES, ossl_shake_256_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", FIPS_DEFAULT_PROPERTIES,
      ossl_keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", FIPS_DEFAULT_PROPERTIES,
      ossl_keccak_kmac_256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE fips_ciphers[] = {
    /* Our primary name[:ASN.1 OID name][:our older names] */
    ALG("AES-256-ECB", ossl_aes256ecb_functions),
    ALG("AES-192-ECB", ossl_aes192ecb_functions),
    ALG("AES-128-ECB", ossl_aes128ecb_functions),
    ALG("AES-256-CBC:AES256", ossl_aes256cbc_functions),
    ALG("AES-192-CBC:AES192", ossl_aes192cbc_functions),
    ALG("AES-128-CBC:AES128", ossl_aes128cbc_functions),
    ALG("AES-256-CBC-CTS", ossl_aes256cbc_cts_functions),
    ALG("AES-192-CBC-CTS", ossl_aes192cbc_cts_functions),
    ALG("AES-128-CBC-CTS", ossl_aes128cbc_cts_functions),
    ALG("AES-256-OFB", ossl_aes256ofb_functions),
    ALG("AES-192-OFB", ossl_aes192ofb_functions),
    ALG("AES-128-OFB", ossl_aes128ofb_functions),
    ALG("AES-256-CFB", ossl_aes256cfb_functions),
    ALG("AES-192-CFB", ossl_aes192cfb_functions),
    ALG("AES-128-CFB", ossl_aes128cfb_functions),
    ALG("AES-256-CFB1", ossl_aes256cfb1_functions),
    ALG("AES-192-CFB1", ossl_aes192cfb1_functions),
    ALG("AES-128-CFB1", ossl_aes128cfb1_functions),
    ALG("AES-256-CFB8", ossl_aes256cfb8_functions),
    ALG("AES-192-CFB8", ossl_aes192cfb8_functions),
    ALG("AES-128-CFB8", ossl_aes128cfb8_functions),
    ALG("AES-256-CTR", ossl_aes256ctr_functions),
    ALG("AES-192-CTR", ossl_aes192ctr_functions),
    ALG("AES-128-CTR", ossl_aes128ctr_functions),
    ALG("AES-256-XTS", ossl_aes256xts_functions),
    ALG("AES-128-XTS", ossl_aes128xts_functions),
    ALG("AES-256-GCM:id-aes256-GCM", ossl_aes256gcm_functions),
    ALG("AES-192-GCM:id-aes192-GCM", ossl_aes192gcm_functions),
    ALG("AES-128-GCM:id-aes128-GCM", ossl_aes128gcm_functions),
    ALG("AES-256-CCM:id-aes256-CCM", ossl_aes256ccm_functions),
    ALG("AES-192-CCM:id-aes192-CCM", ossl_aes192ccm_functions),
    ALG("AES-128-CCM:id-aes128-CCM", ossl_aes128ccm_functions),
    ALG("AES-256-WRAP:id-aes256-wrap:AES256-WRAP", ossl_aes256wrap_functions),
    ALG("AES-192-WRAP:id-aes192-wrap:AES192-WRAP", ossl_aes192wrap_functions),
    ALG("AES-128-WRAP:id-aes128-wrap:AES128-WRAP", ossl_aes128wrap_functions),
    ALG("AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD",
        ossl_aes256wrappad_functions),
    ALG("AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD",
        ossl_aes192wrappad_functions),
    ALG("AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD",
        ossl_aes128wrappad_functions),
    ALG("AES-256-WRAP-INV:AES256-WRAP-INV", ossl_aes256wrapinv_functions),
    ALG("AES-192-WRAP-INV:AES192-WRAP-INV", ossl_aes192wrapinv_functions),
    ALG("AES-128-WRAP-INV:AES128-WRAP-INV", ossl_aes128wrapinv_functions),
    ALG("AES-256-WRAP-PAD-INV:AES256-WRAP-PAD-INV",
        ossl_aes256wrappadinv_functions),
    ALG("AES-192-WRAP-PAD-INV:AES192-WRAP-PAD-INV",
        ossl_aes192wrappadinv_functions),
    ALG("AES-128-WRAP-PAD-INV:AES128-WRAP-PAD-INV",
        ossl_aes128wrappadinv_functions),
    ALGC("AES-128-CBC-HMAC-SHA1", ossl_aes128cbc_hmac_sha1_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-256-CBC-HMAC-SHA1", ossl_aes256cbc_hmac_sha1_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-128-CBC-HMAC-SHA256", ossl_aes128cbc_hmac_sha256_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha256),
    ALGC("AES-256-CBC-HMAC-SHA256", ossl_aes256cbc_hmac_sha256_functions,
         ossl_cipher_capable_aes_cbc_hmac_sha256),
#ifndef OPENSSL_NO_DES
    ALG("DES-EDE3-ECB:DES-EDE3", ossl_tdes_ede3_ecb_functions),
    ALG("DES-EDE3-CBC:DES3", ossl_tdes_ede3_cbc_functions),
#endif  /* OPENSSL_NO_DES */
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_fips_ciphers[OSSL_NELEM(fips_ciphers)];

static const OSSL_ALGORITHM fips_macs[] = {
#ifndef OPENSSL_NO_CMAC
    { "CMAC", FIPS_DEFAULT_PROPERTIES, ossl_cmac_functions },
#endif
    { "GMAC", FIPS_DEFAULT_PROPERTIES, ossl_gmac_functions },
    { "HMAC", FIPS_DEFAULT_PROPERTIES, ossl_hmac_functions },
    { "KMAC-128:KMAC128", FIPS_DEFAULT_PROPERTIES, ossl_kmac128_functions },
    { "KMAC-256:KMAC256", FIPS_DEFAULT_PROPERTIES, ossl_kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_hkdf_functions },
    { "SSKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_sskdf_functions },
    { "PBKDF2", FIPS_DEFAULT_PROPERTIES, ossl_kdf_pbkdf2_functions },
    { "SSHKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_sshkdf_functions },
    { "X963KDF:X942KDF-CONCAT", FIPS_DEFAULT_PROPERTIES,
      ossl_kdf_x963_kdf_functions },
    { "X942KDF-ASN1:X942KDF", FIPS_DEFAULT_PROPERTIES,
      ossl_kdf_x942_kdf_functions },
    { "TLS1-PRF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_tls1_prf_functions },
    { "KBKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_rands[] = {
    { "CTR-DRBG", FIPS_DEFAULT_PROPERTIES, ossl_drbg_ctr_functions },
    { "HASH-DRBG", FIPS_DEFAULT_PROPERTIES, ossl_drbg_hash_functions },
    { "HMAC-DRBG", FIPS_DEFAULT_PROPERTIES, ossl_drbg_ossl_hmac_functions },
    { "TEST-RAND", FIPS_UNAPPROVED_PROPERTIES, ossl_test_rng_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", FIPS_DEFAULT_PROPERTIES, ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { "ECDH", FIPS_DEFAULT_PROPERTIES, ossl_ecdh_keyexch_functions },
    { "X25519", FIPS_DEFAULT_PROPERTIES, ossl_x25519_keyexch_functions },
    { "X448", FIPS_DEFAULT_PROPERTIES, ossl_x448_keyexch_functions },
#endif
    { "TLS1-PRF", FIPS_DEFAULT_PROPERTIES,
      ossl_kdf_tls1_prf_keyexch_functions },
    { "HKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_hkdf_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", FIPS_DEFAULT_PROPERTIES,
      ossl_dsa_signature_functions },
#endif
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES,
      ossl_rsa_signature_functions },
#ifndef OPENSSL_NO_EC
    { "ED25519", FIPS_DEFAULT_PROPERTIES, ossl_ed25519_signature_functions },
    { "ED448", FIPS_DEFAULT_PROPERTIES, ossl_ed448_signature_functions },
    { "ECDSA", FIPS_DEFAULT_PROPERTIES, ossl_ecdsa_signature_functions },
#endif
    { "HMAC", FIPS_DEFAULT_PROPERTIES,
      ossl_mac_legacy_hmac_signature_functions },
#ifndef OPENSSL_NO_CMAC
    { "CMAC", FIPS_DEFAULT_PROPERTIES,
      ossl_mac_legacy_cmac_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_asym_cipher[] = {
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES,
      ossl_rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_asym_kem[] = {
    { "RSA", FIPS_DEFAULT_PROPERTIES, ossl_rsa_asym_kem_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", FIPS_DEFAULT_PROPERTIES, ossl_dh_keymgmt_functions },
    { "DHX:X9.42 DH:dhpublicnumber", FIPS_DEFAULT_PROPERTIES,
      ossl_dhx_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA", FIPS_DEFAULT_PROPERTIES, ossl_dsa_keymgmt_functions },
#endif
    { "RSA:rsaEncryption", FIPS_DEFAULT_PROPERTIES,
      ossl_rsa_keymgmt_functions },
    { "RSA-PSS:RSASSA-PSS", FIPS_DEFAULT_PROPERTIES,
      ossl_rsapss_keymgmt_functions },
#ifndef OPENSSL_NO_EC
    { "EC:id-ecPublicKey", FIPS_DEFAULT_PROPERTIES, ossl_ec_keymgmt_functions },
    { "X25519", FIPS_DEFAULT_PROPERTIES, ossl_x25519_keymgmt_functions },
    { "X448", FIPS_DEFAULT_PROPERTIES, ossl_x448_keymgmt_functions },
    { "ED25519", FIPS_DEFAULT_PROPERTIES, ossl_ed25519_keymgmt_functions },
    { "ED448", FIPS_DEFAULT_PROPERTIES, ossl_ed448_keymgmt_functions },
#endif
    { "TLS1-PRF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_keymgmt_functions },
    { "HKDF", FIPS_DEFAULT_PROPERTIES, ossl_kdf_keymgmt_functions },
    { "HMAC", FIPS_DEFAULT_PROPERTIES, ossl_mac_legacy_keymgmt_functions },
#ifndef OPENSSL_NO_CMAC
    { "CMAC", FIPS_DEFAULT_PROPERTIES,
      ossl_cossl_mac_legacy_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(void *provctx, int operation_id,
                                        int *no_cache)
{
    *no_cache = 0;

    if (!ossl_prov_is_running())
        return NULL;

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    case OSSL_OP_CIPHER:
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
    case OSSL_OP_KEM:
        return fips_asym_kem;
    }
    return NULL;
}

static void fips_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

static void fips_intern_teardown(void *provctx)
{
    /*
     * We know that the library context is the same as for the outer provider,
     * so no need to destroy it here.
     */
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))fips_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fips_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))provider_get_capabilities },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))fips_self_test },
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
    OSSL_LIB_CTX *libctx = NULL;

    if (!ossl_prov_seeding_from_dispatch(in))
        return 0;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
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
        case OSSL_FUNC_SELF_TEST_CB:
            c_stcbfn = OSSL_FUNC_self_test_cb(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    set_self_test_cb(handle);

    if (!c_get_params(handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    /* Disable the conditional error check if is disabled in the fips config file*/
    if (selftest_params.conditional_error_check != NULL
        && strcmp(selftest_params.conditional_error_check, "0") == 0)
        SELF_TEST_disable_conditional_error_state();

    /* Disable the security check if is disabled in the fips config file*/
    if (fips_security_check_option != NULL
        && strcmp(fips_security_check_option, "0") == 0)
        fips_security_checks = 0;

    /*  Create a context. */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new()) == NULL) {
        /*
         * We free libctx separately here and only here because it hasn't
         * been attached to *provctx.  All other error paths below rely
         * solely on fips_teardown.
         */
        OSSL_LIB_CTX_free(libctx);
        goto err;
    }
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    if ((fgbl = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_FIPS_PROV_INDEX,
                                      &fips_prov_ossl_ctx_method)) == NULL)
        goto err;

    fgbl->handle = handle;

    ossl_prov_cache_exported_algorithms(fips_ciphers, exported_fips_ciphers);

    selftest_params.libctx = libctx;
    if (!SELF_TEST_post(&selftest_params, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
        goto err;
    }

    /* TODO(3.0): Tests will hang if this is removed */
    (void)RAND_get0_public(libctx);

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
    OSSL_FUNC_core_get_libctx_fn *c_internal_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_internal_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            break;
        }
    }

    if (c_internal_get_libctx == NULL)
        return 0;

    if ((*provctx = ossl_prov_ctx_new()) == NULL)
        return 0;

    /*
     * Using the parent library context only works because we are a built-in
     * internal provider. This is not something that most providers would be
     * able to do.
     */
    ossl_prov_ctx_set0_libctx(*provctx,
                              (OSSL_LIB_CTX *)c_internal_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);

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
 * passed caller argument is an OSSL_LIB_CTX pointer (since the same routine
 * is also called from other parts of libcrypto, which all pass around a
 * OSSL_LIB_CTX pointer)
 */
const OSSL_CORE_HANDLE *FIPS_get_core_handle(OSSL_LIB_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = ossl_lib_ctx_get_data(libctx,
                                              OSSL_LIB_CTX_FIPS_PROV_INDEX,
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

int FIPS_security_check_enabled(void)
{
    return fips_security_checks;
}

void OSSL_SELF_TEST_get_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK **cb,
                                 void **cbarg)
{
    if (libctx == NULL)
        libctx = selftest_params.libctx;

    if (c_stcbfn != NULL && c_get_libctx != NULL) {
        /* Get the parent libctx */
        c_stcbfn(c_get_libctx(FIPS_get_core_handle(libctx)), cb, cbarg);
    } else {
        if (cb != NULL)
            *cb = NULL;
        if (cbarg != NULL)
            *cbarg = NULL;
    }
}
