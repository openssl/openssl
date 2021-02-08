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
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
#include "internal/nelem.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn deflt_gettable_params;
static OSSL_FUNC_provider_get_params_fn deflt_get_params;
static OSSL_FUNC_provider_query_operation_fn deflt_query;

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM deflt_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *deflt_gettable_params(void *provctx)
{
    return deflt_param_types;
}

static int deflt_get_params(void *provctx, OSSL_PARAM params[])
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
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
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
 *
 * Algorithm names are case insensitive, but we use all caps in our "canonical"
 * names for consistency.
 */
static const OSSL_ALGORITHM deflt_digests[] = {
    /* Our primary name:NIST name[:our older names] */
    { "SHA1:SHA-1:SSL3-SHA1", "provider=default", ossl_sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "provider=default", ossl_sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "provider=default", ossl_sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "provider=default", ossl_sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "provider=default", ossl_sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "provider=default",
      ossl_sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "provider=default",
      ossl_sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "provider=default", ossl_sha3_224_functions },
    { "SHA3-256", "provider=default", ossl_sha3_256_functions },
    { "SHA3-384", "provider=default", ossl_sha3_384_functions },
    { "SHA3-512", "provider=default", ossl_sha3_512_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * the KMAC-128 and KMAC-256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "provider=default",
      ossl_keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "provider=default",
      ossl_keccak_kmac_256_functions },

    /* Our primary name:NIST name */
    { "SHAKE-128:SHAKE128", "provider=default", ossl_shake_128_functions },
    { "SHAKE-256:SHAKE256", "provider=default", ossl_shake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    /*
     * https://blake2.net/ doesn't specify size variants,
     * but mentions that Bouncy Castle uses the names
     * BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, and BLAKE2b-512
     * If we assume that "2b" and "2s" are versions, that pattern
     * fits with ours.  We also add our historical names.
     */
    { "BLAKE2S-256:BLAKE2s256", "provider=default", ossl_blake2s256_functions },
    { "BLAKE2B-512:BLAKE2b512", "provider=default", ossl_blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { "SM3", "provider=default", ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { "MD5:SSL3-MD5", "provider=default", ossl_md5_functions },
    { "MD5-SHA1", "provider=default", ossl_md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE deflt_ciphers[] = {
    ALG("NULL", ossl_null_functions),
    ALG("AES-256-ECB", ossl_aes256ecb_functions),
    ALG("AES-192-ECB", ossl_aes192ecb_functions),
    ALG("AES-128-ECB", ossl_aes128ecb_functions),
    ALG("AES-256-CBC:AES256", ossl_aes256cbc_functions),
    ALG("AES-192-CBC:AES192", ossl_aes192cbc_functions),
    ALG("AES-128-CBC:AES128", ossl_aes128cbc_functions),
    ALG("AES-128-CBC-CTS", ossl_aes128cbc_cts_functions),
    ALG("AES-192-CBC-CTS", ossl_aes192cbc_cts_functions),
    ALG("AES-256-CBC-CTS", ossl_aes256cbc_cts_functions),
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
#ifndef OPENSSL_NO_OCB
    ALG("AES-256-OCB", ossl_aes256ocb_functions),
    ALG("AES-192-OCB", ossl_aes192ocb_functions),
    ALG("AES-128-OCB", ossl_aes128ocb_functions),
#endif /* OPENSSL_NO_OCB */
#ifndef OPENSSL_NO_SIV
    ALG("AES-128-SIV", ossl_aes128siv_functions),
    ALG("AES-192-SIV", ossl_aes192siv_functions),
    ALG("AES-256-SIV", ossl_aes256siv_functions),
#endif /* OPENSSL_NO_SIV */
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
#ifndef OPENSSL_NO_ARIA
    ALG("ARIA-256-GCM", ossl_aria256gcm_functions),
    ALG("ARIA-192-GCM", ossl_aria192gcm_functions),
    ALG("ARIA-128-GCM", ossl_aria128gcm_functions),
    ALG("ARIA-256-CCM", ossl_aria256ccm_functions),
    ALG("ARIA-192-CCM", ossl_aria192ccm_functions),
    ALG("ARIA-128-CCM", ossl_aria128ccm_functions),
    ALG("ARIA-256-ECB", ossl_aria256ecb_functions),
    ALG("ARIA-192-ECB", ossl_aria192ecb_functions),
    ALG("ARIA-128-ECB", ossl_aria128ecb_functions),
    ALG("ARIA-256-CBC:ARIA256", ossl_aria256cbc_functions),
    ALG("ARIA-192-CBC:ARIA192", ossl_aria192cbc_functions),
    ALG("ARIA-128-CBC:ARIA128", ossl_aria128cbc_functions),
    ALG("ARIA-256-OFB", ossl_aria256ofb_functions),
    ALG("ARIA-192-OFB", ossl_aria192ofb_functions),
    ALG("ARIA-128-OFB", ossl_aria128ofb_functions),
    ALG("ARIA-256-CFB", ossl_aria256cfb_functions),
    ALG("ARIA-192-CFB", ossl_aria192cfb_functions),
    ALG("ARIA-128-CFB", ossl_aria128cfb_functions),
    ALG("ARIA-256-CFB1", ossl_aria256cfb1_functions),
    ALG("ARIA-192-CFB1", ossl_aria192cfb1_functions),
    ALG("ARIA-128-CFB1", ossl_aria128cfb1_functions),
    ALG("ARIA-256-CFB8", ossl_aria256cfb8_functions),
    ALG("ARIA-192-CFB8", ossl_aria192cfb8_functions),
    ALG("ARIA-128-CFB8", ossl_aria128cfb8_functions),
    ALG("ARIA-256-CTR", ossl_aria256ctr_functions),
    ALG("ARIA-192-CTR", ossl_aria192ctr_functions),
    ALG("ARIA-128-CTR", ossl_aria128ctr_functions),
#endif /* OPENSSL_NO_ARIA */
#ifndef OPENSSL_NO_CAMELLIA
    ALG("CAMELLIA-256-ECB", ossl_camellia256ecb_functions),
    ALG("CAMELLIA-192-ECB", ossl_camellia192ecb_functions),
    ALG("CAMELLIA-128-ECB", ossl_camellia128ecb_functions),
    ALG("CAMELLIA-256-CBC:CAMELLIA256", ossl_camellia256cbc_functions),
    ALG("CAMELLIA-192-CBC:CAMELLIA192", ossl_camellia192cbc_functions),
    ALG("CAMELLIA-128-CBC:CAMELLIA128", ossl_camellia128cbc_functions),
    ALG("CAMELLIA-256-OFB", ossl_camellia256ofb_functions),
    ALG("CAMELLIA-192-OFB", ossl_camellia192ofb_functions),
    ALG("CAMELLIA-128-OFB", ossl_camellia128ofb_functions),
    ALG("CAMELLIA-256-CFB", ossl_camellia256cfb_functions),
    ALG("CAMELLIA-192-CFB", ossl_camellia192cfb_functions),
    ALG("CAMELLIA-128-CFB", ossl_camellia128cfb_functions),
    ALG("CAMELLIA-256-CFB1", ossl_camellia256cfb1_functions),
    ALG("CAMELLIA-192-CFB1", ossl_camellia192cfb1_functions),
    ALG("CAMELLIA-128-CFB1", ossl_camellia128cfb1_functions),
    ALG("CAMELLIA-256-CFB8", ossl_camellia256cfb8_functions),
    ALG("CAMELLIA-192-CFB8", ossl_camellia192cfb8_functions),
    ALG("CAMELLIA-128-CFB8", ossl_camellia128cfb8_functions),
    ALG("CAMELLIA-256-CTR", ossl_camellia256ctr_functions),
    ALG("CAMELLIA-192-CTR", ossl_camellia192ctr_functions),
    ALG("CAMELLIA-128-CTR", ossl_camellia128ctr_functions),
#endif /* OPENSSL_NO_CAMELLIA */
#ifndef OPENSSL_NO_DES
    ALG("DES-EDE3-ECB:DES-EDE3", ossl_tdes_ede3_ecb_functions),
    ALG("DES-EDE3-CBC:DES3", ossl_tdes_ede3_cbc_functions),
    ALG("DES-EDE3-OFB", ossl_tdes_ede3_ofb_functions),
    ALG("DES-EDE3-CFB", ossl_tdes_ede3_cfb_functions),
    ALG("DES-EDE3-CFB8", ossl_tdes_ede3_cfb8_functions),
    ALG("DES-EDE3-CFB1", ossl_tdes_ede3_cfb1_functions),
    ALG("DES3-WRAP:id-smime-alg-CMS3DESwrap", ossl_tdes_wrap_cbc_functions),
    ALG("DES-EDE-ECB:DES-EDE", ossl_tdes_ede2_ecb_functions),
    ALG("DES-EDE-CBC", ossl_tdes_ede2_cbc_functions),
    ALG("DES-EDE-OFB", ossl_tdes_ede2_ofb_functions),
    ALG("DES-EDE-CFB", ossl_tdes_ede2_cfb_functions),
#endif /* OPENSSL_NO_DES */
#ifndef OPENSSL_NO_SM4
    ALG("SM4-ECB", ossl_sm4128ecb_functions),
    ALG("SM4-CBC:SM4", ossl_sm4128cbc_functions),
    ALG("SM4-CTR", ossl_sm4128ctr_functions),
    ALG("SM4-OFB:SM4-OFB128", ossl_sm4128ofb128_functions),
    ALG("SM4-CFB:SM4-CFB128", ossl_sm4128cfb128_functions),
#endif /* OPENSSL_NO_SM4 */
#ifndef OPENSSL_NO_CHACHA
    ALG("ChaCha20", ossl_chacha20_functions),
# ifndef OPENSSL_NO_POLY1305
    ALG("ChaCha20-Poly1305", ossl_chacha20_ossl_poly1305_functions),
# endif /* OPENSSL_NO_POLY1305 */
#endif /* OPENSSL_NO_CHACHA */
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_ciphers[OSSL_NELEM(deflt_ciphers)];

static const OSSL_ALGORITHM deflt_macs[] = {
#ifndef OPENSSL_NO_BLAKE2
    { "BLAKE2BMAC", "provider=default", ossl_blake2bmac_functions },
    { "BLAKE2SMAC", "provider=default", ossl_blake2smac_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "provider=default", ossl_cmac_functions },
#endif
    { "GMAC", "provider=default", ossl_gmac_functions },
    { "HMAC", "provider=default", ossl_hmac_functions },
    { "KMAC-128:KMAC128", "provider=default", ossl_kmac128_functions },
    { "KMAC-256:KMAC256", "provider=default", ossl_kmac256_functions },
#ifndef OPENSSL_NO_SIPHASH
    { "SIPHASH", "provider=default", ossl_siphash_functions },
#endif
#ifndef OPENSSL_NO_POLY1305
    { "POLY1305", "provider=default", ossl_poly1305_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_kdfs[] = {
    { "HKDF", "provider=default", ossl_kdf_hkdf_functions },
    { "SSKDF", "provider=default", ossl_kdf_sskdf_functions },
    { "PBKDF2", "provider=default", ossl_kdf_pbkdf2_functions },
    { "PKCS12KDF", "provider=default", ossl_kdf_pkcs12_functions },
    { "SSHKDF", "provider=default", ossl_kdf_sshkdf_functions },
    { "X963KDF:X942KDF-CONCAT", "provider=default", ossl_kdf_x963_kdf_functions },
    { "TLS1-PRF", "provider=default", ossl_kdf_tls1_prf_functions },
    { "KBKDF", "provider=default", ossl_kdf_kbkdf_functions },
    { "X942KDF-ASN1:X942KDF", "provider=default", ossl_kdf_x942_kdf_functions },
#ifndef OPENSSL_NO_SCRYPT
    { "SCRYPT:id-scrypt", "provider=default", ossl_kdf_scrypt_functions },
#endif
    { "KRB5KDF", "provider=default", ossl_kdf_krb5kdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "provider=default", ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { "ECDH", "provider=default", ossl_ecdh_keyexch_functions },
    { "X25519", "provider=default", ossl_x25519_keyexch_functions },
    { "X448", "provider=default", ossl_x448_keyexch_functions },
#endif
    { "TLS1-PRF", "provider=default", ossl_kdf_tls1_prf_keyexch_functions },
    { "HKDF", "provider=default", ossl_kdf_hkdf_keyexch_functions },
    { "SCRYPT:id-scrypt", "provider=default",
      ossl_kdf_scrypt_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_rands[] = {
    { "CTR-DRBG", "provider=default", ossl_drbg_ctr_functions },
    { "HASH-DRBG", "provider=default", ossl_drbg_hash_functions },
    { "HMAC-DRBG", "provider=default", ossl_drbg_ossl_hmac_functions },
    { "SEED-SRC", "provider=default", ossl_seed_src_functions },
    { "TEST-RAND", "provider=default", ossl_test_rng_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "provider=default", ossl_dsa_signature_functions },
#endif
    { "RSA:rsaEncryption", "provider=default", ossl_rsa_signature_functions },
#ifndef OPENSSL_NO_EC
    { "ED25519", "provider=default", ossl_ed25519_signature_functions },
    { "ED448", "provider=default", ossl_ed448_signature_functions },
    { "ECDSA", "provider=default", ossl_ecdsa_signature_functions },
# ifndef OPENSSL_NO_SM2
    { "SM2", "provider=default", ossl_sm2_signature_functions },
# endif
#endif
    { "HMAC", "provider=default", ossl_mac_legacy_hmac_signature_functions },
    { "SIPHASH", "provider=default",
      ossl_mac_legacy_siphash_signature_functions },
#ifndef OPENSSL_NO_POLY1305
    { "POLY1305", "provider=default",
      ossl_mac_legacy_poly1305_signature_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "provider=default", ossl_mac_legacy_cmac_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_asym_cipher[] = {
    { "RSA:rsaEncryption", "provider=default", ossl_rsa_asym_cipher_functions },
#ifndef OPENSSL_NO_SM2
    { "SM2", "provider=default", ossl_sm2_asym_cipher_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_asym_kem[] = {
    { "RSA", "provider=default", ossl_rsa_asym_kem_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "provider=default", ossl_dh_keymgmt_functions },
    { "DHX:X9.42 DH:dhpublicnumber", "provider=default",
      ossl_dhx_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "provider=default", ossl_dsa_keymgmt_functions },
#endif
    { "RSA:rsaEncryption", "provider=default", ossl_rsa_keymgmt_functions },
    { "RSA-PSS:RSASSA-PSS", "provider=default", ossl_rsapss_keymgmt_functions },
#ifndef OPENSSL_NO_EC
    { "EC:id-ecPublicKey", "provider=default", ossl_ec_keymgmt_functions },
    { "X25519", "provider=default", ossl_x25519_keymgmt_functions },
    { "X448", "provider=default", ossl_x448_keymgmt_functions },
    { "ED25519", "provider=default", ossl_ed25519_keymgmt_functions },
    { "ED448", "provider=default", ossl_ed448_keymgmt_functions },
#endif
    { "TLS1-PRF", "provider=default", ossl_kdf_keymgmt_functions },
    { "HKDF", "provider=default", ossl_kdf_keymgmt_functions },
    { "SCRYPT:id-scrypt", "provider=default", ossl_kdf_keymgmt_functions },
    { "HMAC", "provider=default", ossl_mac_legacy_keymgmt_functions },
    { "SIPHASH", "provider=default", ossl_mac_legacy_keymgmt_functions },
#ifndef OPENSSL_NO_POLY1305
    { "POLY1305", "provider=default", ossl_mac_legacy_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "provider=default", ossl_cossl_mac_legacy_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_SM2
    { "SM2", "provider=default", ossl_sm2_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_encoder[] = {
#define ENCODER_PROVIDER "default"
#include "encoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM deflt_decoder[] = {
#define DECODER_PROVIDER "default"
#include "decoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};

static const OSSL_ALGORITHM deflt_store[] = {
#define STORE(name, _fips, func_table)                           \
    { name, "provider=default,fips=" _fips, (func_table) },

#include "stores.inc"
    { NULL, NULL, NULL }
#undef STORE
};

static const OSSL_ALGORITHM *deflt_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return deflt_digests;
    case OSSL_OP_CIPHER:
        return exported_ciphers;
    case OSSL_OP_MAC:
        return deflt_macs;
    case OSSL_OP_KDF:
        return deflt_kdfs;
    case OSSL_OP_RAND:
        return deflt_rands;
    case OSSL_OP_KEYMGMT:
        return deflt_keymgmt;
    case OSSL_OP_KEYEXCH:
        return deflt_keyexch;
    case OSSL_OP_SIGNATURE:
        return deflt_signature;
    case OSSL_OP_ASYM_CIPHER:
        return deflt_asym_cipher;
    case OSSL_OP_KEM:
        return deflt_asym_kem;
    case OSSL_OP_ENCODER:
        return deflt_encoder;
    case OSSL_OP_DECODER:
        return deflt_decoder;
    case OSSL_OP_STORE:
        return deflt_store;
    }
    return NULL;
}


static void deflt_teardown(void *provctx)
{
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))deflt_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))deflt_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))deflt_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))deflt_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))provider_get_capabilities },
    { 0, NULL }
};

OSSL_provider_init_fn ossl_default_provider_init;

int ossl_default_provider_init(const OSSL_CORE_HANDLE *handle,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    BIO_METHOD *corebiometh;

    if (!ossl_prov_bio_from_dispatch(in)
            || !ossl_prov_seeding_from_dispatch(in))
        return 0;
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
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
            || (corebiometh = bio_prov_init_bio_method()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx,
                                       (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);

    *out = deflt_dispatch_table;
    ossl_prov_cache_exported_algorithms(deflt_ciphers, exported_ciphers);

    return 1;
}
