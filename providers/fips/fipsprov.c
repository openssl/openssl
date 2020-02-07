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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* TODO(3.0): Needed for dummy_evp_call(). To be removed */
#include <openssl/sha.h>
#include <openssl/rand_drbg.h>
#include <openssl/ec.h>
#include <openssl/fips_names.h>

#include "internal/cryptlib.h"
#include "internal/property.h"
#include "internal/nelem.h"
#include "openssl/param_build.h"
#include "crypto/evp.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/provider_util.h"
#include "self_test.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=fips,fips=yes", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

extern OSSL_core_thread_start_fn *c_thread_start;

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OPENSSL_CTX as a parameter.
 */

static SELF_TEST_POST_PARAMS selftest_params;

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params;
static OSSL_core_get_params_fn *c_get_params;
OSSL_core_thread_start_fn *c_thread_start;
static OSSL_core_new_error_fn *c_new_error;
static OSSL_core_set_error_debug_fn *c_set_error_debug;
static OSSL_core_vset_error_fn *c_vset_error;
static OSSL_core_set_error_mark_fn *c_set_error_mark;
static OSSL_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_core_pop_error_to_mark_fn *c_pop_error_to_mark;
static OSSL_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;
static OSSL_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc;
static OSSL_CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc;
static OSSL_CRYPTO_secure_free_fn *c_CRYPTO_secure_free;
static OSSL_CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free;
static OSSL_CRYPTO_secure_allocated_fn *c_CRYPTO_secure_allocated;
static OSSL_BIO_vsnprintf_fn *c_BIO_vsnprintf;

typedef struct fips_global_st {
    const OSSL_PROVIDER *prov;
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
 * stored inside prov->parameters (except for OSSL_PROV_PARAM_MODULE_FILENAME).
 */
static OSSL_PARAM core_params[] =
{
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_MODULE_FILENAME,
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

/* TODO(3.0): To be removed */
static int dummy_evp_call(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, NULL);
    unsigned char dgst[SHA256_DIGEST_LENGTH];
    unsigned int dgstlen;
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *a = NULL, *b = NULL;
    unsigned char randbuf[128];
    RAND_DRBG *drbg = OPENSSL_CTX_get0_public_drbg(libctx);
#ifndef OPENSSL_NO_EC
    EC_KEY *key = NULL;
#endif

    static const char msg[] = "Hello World!";
    static const unsigned char exptd[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };

    if (ctx == NULL || sha256 == NULL || drbg == NULL || kdf == NULL)
        goto err;

    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
        goto err;
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1))
        goto err;
    if (!EVP_DigestFinal(ctx, dgst, &dgstlen))
        goto err;
    if (dgstlen != sizeof(exptd) || memcmp(dgst, exptd, sizeof(exptd)) != 0)
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    BN_CTX_start(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL)
        goto err;
    BN_zero(a);
    if (!BN_one(b)
        || !BN_add(a, a, b)
        || BN_cmp(a, b) != 0)
        goto err;

    if (RAND_DRBG_bytes(drbg, randbuf, sizeof(randbuf)) <= 0)
        goto err;

    if (!BN_rand_ex(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, bnctx))
        goto err;

#ifndef OPENSSL_NO_EC
    /* Do some dummy EC calls */
    key = EC_KEY_new_by_curve_name_ex(libctx, NID_X9_62_prime256v1);
    if (key == NULL)
        goto err;

    if (!EC_KEY_generate_key(key))
        goto err;
#endif

    ret = 1;
 err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);

    EVP_KDF_free(kdf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha256);

#ifndef OPENSSL_NO_EC
    EC_KEY_free(key);
#endif
    return ret;
}

static const OSSL_PARAM *fips_gettable_params(const OSSL_PROVIDER *prov)
{
    return fips_param_types;
}

static int fips_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
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
const char *ossl_prov_util_nid_to_name(int nid)
{
    /* We don't have OBJ_nid2n() in FIPS_MODE so we have an explicit list */

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
    { "SHA1:SHA-1", "provider=fips,fips=yes", sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "provider=fips,fips=yes", sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "provider=fips,fips=yes", sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "provider=fips,fips=yes", sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "provider=fips,fips=yes", sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "provider=fips,fips=yes",
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "provider=fips,fips=yes",
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "provider=fips,fips=yes", sha3_224_functions },
    { "SHA3-256", "provider=fips,fips=yes", sha3_256_functions },
    { "SHA3-384", "provider=fips,fips=yes", sha3_384_functions },
    { "SHA3-512", "provider=fips,fips=yes", sha3_512_functions },
    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "provider=fips,fips=yes", keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "provider=fips,fips=yes", keccak_kmac_256_functions },

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
    { "CMAC", "provider=fips,fips=yes", cmac_functions },
#endif
    { "GMAC", "provider=fips,fips=yes", gmac_functions },
    { "HMAC", "provider=fips,fips=yes", hmac_functions },
    { "KMAC-128:KMAC128", "provider=fips,fips=yes", kmac128_functions },
    { "KMAC-256:KMAC256", "provider=fips,fips=yes", kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", "provider=fips,fips=yes", kdf_hkdf_functions },
    { "SSKDF", "provider=fips,fips=yes", kdf_sskdf_functions },
    { "PBKDF2", "provider=fips,fips=yes", kdf_pbkdf2_functions },
    { "TLS1-PRF", "provider=fips,fips=yes", kdf_tls1_prf_functions },
    { "KBKDF", "provider=fips,fips=yes", kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "provider=fips,fips=yes", dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { "ECDH", "provider=fips,fips=yes", ecdh_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "provider=fips,fips=yes", dsa_signature_functions },
#endif
    { "RSA:rsaEncryption", "provider=fips,fips=yes", rsa_signature_functions },
#ifndef OPENSSL_NO_EC
    { "ECDSA", "provider=fips,fips=yes", ecdsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_asym_cipher[] = {
    { "RSA:rsaEncryption", "provider=fips,fips=yes", rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "provider=fips,fips=yes", dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA", "provider=fips,fips=yes", dsa_keymgmt_functions },
#endif
    { "RSA:rsaEncryption", "provider=fips,fips=yes", rsa_keymgmt_functions },
#ifndef OPENSSL_NO_EC
    { "EC:id-ecPublicKey", "provider=fips,fips=yes", ec_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(OSSL_PROVIDER *prov,
                                         int operation_id,
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

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    /*
     * To release our resources we just need to free the OPENSSL_CTX so we just
     * use OPENSSL_CTX_free directly as our teardown function
     */
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OPENSSL_CTX_free },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fips_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};

/* Functions we provide to ourself */
static const OSSL_DISPATCH intern_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    FIPS_GLOBAL *fgbl;
    OPENSSL_CTX *ctx;
    OSSL_self_test_cb_fn *stcbfn = NULL;
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_get_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_get_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_get_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_get_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            c_set_error_mark = OSSL_get_core_set_error_mark(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            c_clear_last_error_mark = OSSL_get_core_clear_last_error_mark(in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            c_pop_error_to_mark = OSSL_get_core_pop_error_to_mark(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_CRYPTO_malloc = OSSL_get_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_CRYPTO_zalloc = OSSL_get_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_CRYPTO_free = OSSL_get_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            c_CRYPTO_clear_free = OSSL_get_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            c_CRYPTO_realloc = OSSL_get_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            c_CRYPTO_clear_realloc = OSSL_get_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            c_CRYPTO_secure_malloc = OSSL_get_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            c_CRYPTO_secure_zalloc = OSSL_get_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            c_CRYPTO_secure_free = OSSL_get_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            c_CRYPTO_secure_clear_free = OSSL_get_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            c_CRYPTO_secure_allocated = OSSL_get_CRYPTO_secure_allocated(in);
            break;
        case OSSL_FUNC_BIO_NEW_FILE:
            selftest_params.bio_new_file_cb = OSSL_get_BIO_new_file(in);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            selftest_params.bio_new_buffer_cb = OSSL_get_BIO_new_membuf(in);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            selftest_params.bio_read_ex_cb = OSSL_get_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_FREE:
            selftest_params.bio_free_cb = OSSL_get_BIO_free(in);
            break;
        case OSSL_FUNC_BIO_VSNPRINTF:
            c_BIO_vsnprintf = OSSL_get_BIO_vsnprintf(in);
            break;
        case OSSL_FUNC_SELF_TEST_CB: {
            stcbfn = OSSL_get_self_test_cb(in);
            break;
        }
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (stcbfn != NULL && c_get_libctx != NULL) {
        stcbfn(c_get_libctx(provider), &selftest_params.cb,
               &selftest_params.cb_arg);
    }
    else {
        selftest_params.cb = NULL;
        selftest_params.cb_arg = NULL;
    }

    if (!c_get_params(provider, core_params))
        return 0;

    /*  Create a context. */
    if ((ctx = OPENSSL_CTX_new()) == NULL)
        return 0;
    if ((fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                     &fips_prov_ossl_ctx_method)) == NULL) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    fgbl->prov = provider;

    selftest_params.libctx = PROV_LIBRARY_CONTEXT_OF(ctx);
    if (!SELF_TEST_post(&selftest_params, 0)) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    /*
     * TODO(3.0): Remove me. This is just a dummy call to demonstrate making
     * EVP calls from within the FIPS module.
     */
    if (!dummy_evp_call(ctx)) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    *out = fips_dispatch_table;
    *provctx = ctx;

    return 1;
}

/*
 * The internal init function used when the FIPS module uses EVP to call
 * another algorithm also in the FIPS module. This is a recursive call that has
 * been made from within the FIPS module itself. To make this work, we populate
 * the provider context of this inner instance with the same library context
 * that was used in the EVP call that initiated this recursive call.
 */
OSSL_provider_init_fn fips_intern_provider_init;
int fips_intern_provider_init(const OSSL_PROVIDER *provider,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *provctx = c_get_libctx(provider);

    /*
     * Safety measure...  we should get the library context that was
     * created up in OSSL_provider_init().
     */
    if (*provctx == NULL)
        return 0;

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

const OSSL_PROVIDER *FIPS_get_provider(OPENSSL_CTX *ctx)
{
    FIPS_GLOBAL *fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                             &fips_prov_ossl_ctx_method);

    if (fgbl == NULL)
        return NULL;

    return fgbl->prov;
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
