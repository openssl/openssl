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
#include "crypto/evp.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/provider_util.h"
#include "selftest.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "fips=yes", FUNC }, CHECK }
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

/*
 * This routine is currently necessary as bn params are currently processed
 * using BN_native2bn when raw data is received. This means we need to do
 * magic to reverse the order of the bytes to match native format.
 * The array of hexdata is to get around compilers that dont like
 * strings longer than 509 bytes,
 */
static int rawnative_fromhex(const char *hex_data[],
                             unsigned char **native, size_t *nativelen)
{
    int ret = 0;
    unsigned char *data = NULL;
    BIGNUM *bn = NULL;
    int i, slen, datalen, sz;
    char *str = NULL;

    for (slen = 0, i = 0; hex_data[i] != NULL; ++i)
        slen += strlen(hex_data[i]);
    str = OPENSSL_zalloc(slen + 1);
    if (str == NULL)
        return 0;
    for (i = 0; hex_data[i] != NULL; ++i)
        strcat(str, hex_data[i]);

    if (BN_hex2bn(&bn, str) <= 0)
        return 0;

    datalen = slen / 2;
    data = (unsigned char *)str; /* reuse the str buffer */

    sz = BN_bn2nativepad(bn, data, datalen);
    if (sz <= 0)
        goto err;
    ret = 1;
    *native = data;
    *nativelen = datalen;
    data = NULL; /* so it does not get freed */
err:
    BN_free(bn);
    OPENSSL_free(data);
    return ret;
}

/* TODO(3.0): To be removed */
static int dummy_evp_call(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, NULL);
    EVP_PKEY_CTX *sctx = NULL, *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM *p;
    OSSL_PARAM params[16];
    unsigned char sig[64];
    size_t siglen, sigdgstlen;
    unsigned char *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;
    unsigned char *dsa_pub = NULL, *dsa_priv = NULL;
    size_t dsa_p_len, dsa_q_len, dsa_g_len, dsa_pub_len, dsa_priv_len;

    /* dsa 2048 */
    static const char *dsa_p_hex[] = {
        "a29b8872ce8b8423b7d5d21d4b02f57e03e9e6b8a258dc16611ba098ab543415"
        "e415f156997a3ee236658fa093260de3ad422e05e046f9ec29161a375f0eb4ef"
        "fcef58285c5d39ed425d7a62ca12896c4a92cb1946f2952a48133f07da364d1b"
        "df6b0f7139983e693c80059b0eacd1479ba9f2857754ede75f112b07ebbf3534",
        "8bbf3e01e02f2d473de39453f99dd2367541caca3ba01166343d7b5b58a37bd1"
        "b7521db2f13b86707132fe09f4cd09dc1618fa3401ebf9cc7b19fa94aa472088"
        "133d6cb2d35c1179c8c8ff368758d507d9f9a17d46c110fe3144ce9b022b42e4"
        "19eb4f5388613bfc3e26241a432e8706bc58ef76117278deab6cf692618291b7",
         NULL
    };
    static const char *dsa_q_hex[] = {
        "a3bfd9ab7884794e383450d5891dc18b65157bdcfcdac51518902867",
        NULL
    };
    static const char *dsa_g_hex[] = {
        "6819278869c7fd3d2d7b77f77e8150d9ad433bea3ba85efc80415aa3545f78f7"
        "2296f06cb19ceda06c94b0551cfe6e6f863e31d1de6eed7dab8b0c9df231e084"
        "34d1184f91d033696bb382f8455e9888f5d31d4784ec40120246f4bea61794bb"
        "a5866f09746463bdf8e9e108cd9529c3d0f6df80316e2e70aaeb1b26cdb8ad97",
        "bc3d287e0b8d616c42e65b87db20deb7005bc416747a6470147a68a7820388eb"
        "f44d52e0628af9cf1b7166d03465f35acc31b6110c43dabc7c5d591e671eaf7c"
        "252c1c145336a1a4ddf13244d55e835680cab2533b82df2efe55ec18c1e6cd00"
        "7bb089758bb17c2cbe14441bd093ae66e5976d53733f4fa3269701d31d23d467",
        NULL
    };
    static const char *dsa_pub_hex[] = {
        "a012b3b170b307227957b7ca2061a816ac7a2b3d9ae995a5119c385b603bf6f6"
        "c5de4dc5ecb5dfa4a41c68662eb25b638b7e2620ba898d07da6c4991e76cc0ec"
        "d1ad3421077067e47c18f58a92a72ad43199ecb7bd84e7d3afb9019f0e9dd0fb"
        "aa487300b13081e33c902876436f7b03c345528481d362815e24fe59dac5ac34",
        "660d4c8a76cb99a7c7de93eb956cd6bc88e58d901034944a094b01803a43c672"
        "b9688c0e01d8f4fc91c62a3f88021f7bd6a651b1a88f43aa4ef27653d12bf8b7"
        "099fdf6b461082f8e939107bfd2f7210087d326c375200f1f51e7e74a3413190"
        "1bcd0863521ff8d676c48581868736c5e51b16a4e39215ea0b17c4735974c516",
        NULL
    };
    static const char *dsa_priv_hex[] = {
        "6ccaeef6d73b4e80f11c17b8e9627c036635bac39423505e407e5cb7",
        NULL
    };
    char msg[] = "Hello World!";
    const unsigned char exptd[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };
    unsigned int dgstlen = 0;
    unsigned char dgst[SHA256_DIGEST_LENGTH];
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *a = NULL, *b = NULL;
    unsigned char randbuf[128];
    RAND_DRBG *drbg = OPENSSL_CTX_get0_public_drbg(libctx);
#ifndef OPENSSL_NO_EC
    EC_KEY *key = NULL;
#endif

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
    if (!rawnative_fromhex(dsa_p_hex, &dsa_p, &dsa_p_len)
            || !rawnative_fromhex(dsa_q_hex, &dsa_q, &dsa_q_len)
            || !rawnative_fromhex(dsa_g_hex, &dsa_g, &dsa_g_len)
            || !rawnative_fromhex(dsa_pub_hex, &dsa_pub, &dsa_pub_len)
            || !rawnative_fromhex(dsa_priv_hex, &dsa_priv, &dsa_priv_len))
        goto err;

    p = params;
    *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, dsa_p, dsa_p_len);
    *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, dsa_q, dsa_q_len);
    *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, dsa_g, dsa_g_len);
    *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_DSA_PUB_KEY,
                                   dsa_pub, dsa_pub_len);
    *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_DSA_PRIV_KEY,
                                   dsa_priv, dsa_priv_len);
    *p = OSSL_PARAM_construct_end();

    kctx = EVP_PKEY_CTX_new_from_name(libctx, SN_dsa, "");
    if (kctx == NULL)
        goto err;
    if (EVP_PKEY_key_fromdata_init(kctx) <= 0
            || EVP_PKEY_fromdata(kctx, &pkey, params) <= 0)
        goto err;

    sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey);
    if (sctx == NULL)
        goto err;;

    if (EVP_PKEY_sign_init(sctx) <= 0)
        goto err;

    /* set signature parameters */
    sigdgstlen = SHA256_DIGEST_LENGTH;
    p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                            SN_sha256,
                                            strlen(SN_sha256) + 1);

    *p++ = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
                                       &sigdgstlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(sctx, params) <= 0)
        goto err;

    if (EVP_PKEY_sign(sctx, sig, &siglen, dgst, sizeof(dgst)) <= 0
            || EVP_PKEY_verify_init(sctx) <= 0
            || EVP_PKEY_verify(sctx, sig, siglen, dgst, sizeof(dgst)) <= 0)
        goto err;
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
    OPENSSL_free(dsa_p);
    OPENSSL_free(dsa_q);
    OPENSSL_free(dsa_g);
    OPENSSL_free(dsa_pub);
    OPENSSL_free(dsa_priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
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
    { "SHA1:SHA-1", "fips=yes", sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "fips=yes", sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "fips=yes", sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "fips=yes", sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "fips=yes", sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "fips=yes",
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "fips=yes",
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "fips=yes", sha3_224_functions },
    { "SHA3-256", "fips=yes", sha3_256_functions },
    { "SHA3-384", "fips=yes", sha3_384_functions },
    { "SHA3-512", "fips=yes", sha3_512_functions },
    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "fips=yes", keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "fips=yes", keccak_kmac_256_functions },

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
    { "CMAC", "fips=yes", cmac_functions },
#endif
    { "GMAC", "fips=yes", gmac_functions },
    { "HMAC", "fips=yes", hmac_functions },
    { "KMAC-128:KMAC128", "fips=yes", kmac128_functions },
    { "KMAC-256:KMAC256", "fips=yes", kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", "fips=yes", kdf_hkdf_functions },
    { "SSKDF", "fips=yes", kdf_sskdf_functions },
    { "PBKDF2", "fips=yes", kdf_pbkdf2_functions },
    { "TLS1-PRF", "fips=yes", kdf_tls1_prf_functions },
    { "KBKDF", "fips=yes", kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "fips=yes", dsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA", "fips=yes", dsa_keymgmt_functions },
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
    case OSSL_OP_SIGNATURE:
        return fips_signature;
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

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
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
        default:
            /* Just ignore anything we don't understand */
            break;
        }
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
