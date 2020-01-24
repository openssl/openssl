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
#include "prov/bio.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"
#include "internal/nelem.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "default=yes", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

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
    { "SHA1:SHA-1", "default=yes", sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "default=yes", sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "default=yes", sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "default=yes", sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "default=yes", sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "default=yes",
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "default=yes",
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "default=yes", sha3_224_functions },
    { "SHA3-256", "default=yes", sha3_256_functions },
    { "SHA3-384", "default=yes", sha3_384_functions },
    { "SHA3-512", "default=yes", sha3_512_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * the KMAC-128 and KMAC-256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "default=yes", keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "default=yes", keccak_kmac_256_functions },

    /* Our primary name:NIST name */
    { "SHAKE-128:SHAKE128", "default=yes", shake_128_functions },
    { "SHAKE-256:SHAKE256", "default=yes", shake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    /*
     * https://blake2.net/ doesn't specify size variants,
     * but mentions that Bouncy Castle uses the names
     * BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, and BLAKE2b-512
     * If we assume that "2b" and "2s" are versions, that pattern
     * fits with ours.  We also add our historical names.
     */
    { "BLAKE2S-256:BLAKE2s256", "default=yes", blake2s256_functions },
    { "BLAKE2B-512:BLAKE2b512", "default=yes", blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { "SM3", "default=yes", sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { "MD5", "default=yes", md5_functions },
    { "MD5-SHA1", "default=yes", md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE deflt_ciphers[] = {
    ALG("NULL", null_functions),
    ALG("AES-256-ECB", aes256ecb_functions),
    ALG("AES-192-ECB", aes192ecb_functions),
    ALG("AES-128-ECB", aes128ecb_functions),
    ALG("AES-256-CBC", aes256cbc_functions),
    ALG("AES-192-CBC", aes192cbc_functions),
    ALG("AES-128-CBC", aes128cbc_functions),
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
#ifndef OPENSSL_NO_OCB
    ALG("AES-256-OCB", aes256ocb_functions),
    ALG("AES-192-OCB", aes192ocb_functions),
    ALG("AES-128-OCB", aes128ocb_functions),
#endif /* OPENSSL_NO_OCB */
#ifndef OPENSSL_NO_SIV
    ALG("AES-128-SIV", aes128siv_functions),
    ALG("AES-192-SIV", aes192siv_functions),
    ALG("AES-256-SIV", aes256siv_functions),
#endif /* OPENSSL_NO_SIV */
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
#ifndef OPENSSL_NO_ARIA
    ALG("ARIA-256-GCM", aria256gcm_functions),
    ALG("ARIA-192-GCM", aria192gcm_functions),
    ALG("ARIA-128-GCM", aria128gcm_functions),
    ALG("ARIA-256-CCM", aria256ccm_functions),
    ALG("ARIA-192-CCM", aria192ccm_functions),
    ALG("ARIA-128-CCM", aria128ccm_functions),
    ALG("ARIA-256-ECB", aria256ecb_functions),
    ALG("ARIA-192-ECB", aria192ecb_functions),
    ALG("ARIA-128-ECB", aria128ecb_functions),
    ALG("ARIA-256-CBC:ARIA256", aria256cbc_functions),
    ALG("ARIA-192-CBC:ARIA192", aria192cbc_functions),
    ALG("ARIA-128-CBC:ARIA128", aria128cbc_functions),
    ALG("ARIA-256-OFB", aria256ofb_functions),
    ALG("ARIA-192-OFB", aria192ofb_functions),
    ALG("ARIA-128-OFB", aria128ofb_functions),
    ALG("ARIA-256-CFB", aria256cfb_functions),
    ALG("ARIA-192-CFB", aria192cfb_functions),
    ALG("ARIA-128-CFB", aria128cfb_functions),
    ALG("ARIA-256-CFB1", aria256cfb1_functions),
    ALG("ARIA-192-CFB1", aria192cfb1_functions),
    ALG("ARIA-128-CFB1", aria128cfb1_functions),
    ALG("ARIA-256-CFB8", aria256cfb8_functions),
    ALG("ARIA-192-CFB8", aria192cfb8_functions),
    ALG("ARIA-128-CFB8", aria128cfb8_functions),
    ALG("ARIA-256-CTR", aria256ctr_functions),
    ALG("ARIA-192-CTR", aria192ctr_functions),
    ALG("ARIA-128-CTR", aria128ctr_functions),
#endif /* OPENSSL_NO_ARIA */
#ifndef OPENSSL_NO_CAMELLIA
    ALG("CAMELLIA-256-ECB", camellia256ecb_functions),
    ALG("CAMELLIA-192-ECB", camellia192ecb_functions),
    ALG("CAMELLIA-128-ECB", camellia128ecb_functions),
    ALG("CAMELLIA-256-CBC:CAMELLIA256", camellia256cbc_functions),
    ALG("CAMELLIA-192-CBC:CAMELLIA192", camellia192cbc_functions),
    ALG("CAMELLIA-128-CBC:CAMELLIA128", camellia128cbc_functions),
    ALG("CAMELLIA-256-OFB", camellia256ofb_functions),
    ALG("CAMELLIA-192-OFB", camellia192ofb_functions),
    ALG("CAMELLIA-128-OFB", camellia128ofb_functions),
    ALG("CAMELLIA-256-CFB", camellia256cfb_functions),
    ALG("CAMELLIA-192-CFB", camellia192cfb_functions),
    ALG("CAMELLIA-128-CFB", camellia128cfb_functions),
    ALG("CAMELLIA-256-CFB1", camellia256cfb1_functions),
    ALG("CAMELLIA-192-CFB1", camellia192cfb1_functions),
    ALG("CAMELLIA-128-CFB1", camellia128cfb1_functions),
    ALG("CAMELLIA-256-CFB8", camellia256cfb8_functions),
    ALG("CAMELLIA-192-CFB8", camellia192cfb8_functions),
    ALG("CAMELLIA-128-CFB8", camellia128cfb8_functions),
    ALG("CAMELLIA-256-CTR", camellia256ctr_functions),
    ALG("CAMELLIA-192-CTR", camellia192ctr_functions),
    ALG("CAMELLIA-128-CTR", camellia128ctr_functions),
#endif /* OPENSSL_NO_CAMELLIA */
#ifndef OPENSSL_NO_DES
    ALG("DES-EDE3-ECB:DES-EDE3", tdes_ede3_ecb_functions),
    ALG("DES-EDE3-CBC:DES3", tdes_ede3_cbc_functions),
    ALG("DES-EDE3-OFB", tdes_ede3_ofb_functions),
    ALG("DES-EDE3-CFB", tdes_ede3_cfb_functions),
    ALG("DES-EDE3-CFB8", tdes_ede3_cfb8_functions),
    ALG("DES-EDE3-CFB1", tdes_ede3_cfb1_functions),
    ALG("DES-EDE-ECB:DES-EDE", tdes_ede2_ecb_functions),
    ALG("DES-EDE-CBC", tdes_ede2_cbc_functions),
    ALG("DES-EDE-OFB", tdes_ede2_ofb_functions),
    ALG("DES-EDE-CFB", tdes_ede2_cfb_functions),
    ALG("DESX-CBC:DESX", tdes_desx_cbc_functions),
    ALG("DES3-WRAP:id-smime-alg-CMS3DESwrap", tdes_wrap_cbc_functions),
    ALG("DES-ECB", des_ecb_functions),
    ALG("DES-CBC:DES", des_cbc_functions),
    ALG("DES-OFB", des_ofb64_functions),
    ALG("DES-CFB", des_cfb64_functions),
    ALG("DES-CFB1", des_cfb1_functions),
    ALG("DES-CFB8", des_cfb8_functions),
#endif /* OPENSSL_NO_DES */
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
#ifndef OPENSSL_NO_CAST
    ALG("CAST5-ECB", cast5128ecb_functions),
    ALG("CAST5-CBC:CAST-CBC:CAST", cast5128cbc_functions),
    ALG("CAST5-OFB", cast564ofb64_functions),
    ALG("CAST5-CFB", cast564cfb64_functions),
#endif /* OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_SEED
    ALG("SEED-ECB", seed128ecb_functions),
    ALG("SEED-CBC:SEED", seed128cbc_functions),
    ALG("SEED-OFB:SEED-OFB128", seed128ofb128_functions),
    ALG("SEED-CFB:SEED-CFB128", seed128cfb128_functions),
#endif /* OPENSSL_NO_SEED */
#ifndef OPENSSL_NO_SM4
    ALG("SM4-ECB", sm4128ecb_functions),
    ALG("SM4-CBC:SM4", sm4128cbc_functions),
    ALG("SM4-CTR", sm4128ctr_functions),
    ALG("SM4-OFB:SM4-OFB128", sm4128ofb128_functions),
    ALG("SM4-CFB:SM4-CFB128", sm4128cfb128_functions),
#endif /* OPENSSL_NO_SM4 */
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
#ifndef OPENSSL_NO_RC2
    ALG("RC2-ECB", rc2128ecb_functions),
    ALG("RC2-CBC", rc2128cbc_functions),
    ALG("RC2-40-CBC", rc240cbc_functions),
    ALG("RC2-64-CBC", rc264cbc_functions),
    ALG("RC2-CFB", rc2128cfb128_functions),
    ALG("RC2-OFB", rc2128ofb128_functions),
#endif /* OPENSSL_NO_RC2 */
#ifndef OPENSSL_NO_CHACHA
    ALG("ChaCha20", chacha20_functions),
# ifndef OPENSSL_NO_POLY1305
    ALG("ChaCha20-Poly1305", chacha20_poly1305_functions),
# endif /* OPENSSL_NO_POLY1305 */
#endif /* OPENSSL_NO_CHACHA */
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_ciphers[OSSL_NELEM(deflt_ciphers)];

static const OSSL_ALGORITHM deflt_macs[] = {
#ifndef OPENSSL_NO_BLAKE2
    { "BLAKE2BMAC", "default=yes", blake2bmac_functions },
    { "BLAKE2SMAC", "default=yes", blake2smac_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "default=yes", cmac_functions },
#endif
    { "GMAC", "default=yes", gmac_functions },
    { "HMAC", "default=yes", hmac_functions },
    { "KMAC-128:KMAC128", "default=yes", kmac128_functions },
    { "KMAC-256:KMAC256", "default=yes", kmac256_functions },
#ifndef OPENSSL_NO_SIPHASH
    { "SIPHASH", "default=yes", siphash_functions },
#endif
#ifndef OPENSSL_NO_POLY1305
    { "POLY1305", "default=yes", poly1305_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_kdfs[] = {
    { "HKDF", "default=yes", kdf_hkdf_functions },
    { "SSKDF", "default=yes", kdf_sskdf_functions },
    { "PBKDF2", "default=yes", kdf_pbkdf2_functions },
    { "SSHKDF", "default=yes", kdf_sshkdf_functions },
    { "X963KDF", "default=yes", kdf_x963_kdf_functions },
    { "TLS1-PRF", "default=yes", kdf_tls1_prf_functions },
    { "KBKDF", "default=yes", kdf_kbkdf_functions },
#ifndef OPENSSL_NO_CMS
    { "X942KDF", "default=yes", kdf_x942_kdf_functions },
#endif
#ifndef OPENSSL_NO_SCRYPT
    { "SCRYPT:id-scrypt", "default=yes", kdf_scrypt_functions },
#endif
    { "KRB5KDF", "default=yes", kdf_krb5kdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "default=yes", dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { "X25519", "default=yes", x25519_keyexch_functions },
    { "X448", "default=yes", x448_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "default=yes", dsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_asym_cipher[] = {
    { "RSA:rsaEncryption", "default=yes", rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "default=yes", dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "default=yes", dsa_keymgmt_functions },
#endif
    { "RSA:rsaEncryption", "default=yes", rsa_keymgmt_functions },
#ifndef OPENSSL_NO_EC
    { "X25519", "default=yes", x25519_keymgmt_functions },
    { "X448", "default=yes", x448_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_serializer[] = {
    { "RSA", "default=yes,format=text,type=private",
      rsa_priv_text_serializer_functions },
    { "RSA", "default=yes,format=text,type=public",
      rsa_pub_text_serializer_functions },
    { "RSA", "default=yes,format=der,type=private",
      rsa_priv_der_serializer_functions },
    { "RSA", "default=yes,format=der,type=public",
      rsa_pub_der_serializer_functions },
    { "RSA", "default=yes,format=pem,type=private",
      rsa_priv_pem_serializer_functions },
    { "RSA", "default=yes,format=pem,type=public",
      rsa_pub_pem_serializer_functions },

#ifndef OPENSSL_NO_DH
    { "DH", "default=yes,format=text,type=private",
      dh_priv_text_serializer_functions },
    { "DH", "default=yes,format=text,type=public",
      dh_pub_text_serializer_functions },
    { "DH", "default=yes,format=text,type=parameters",
      dh_param_text_serializer_functions },
    { "DH", "default=yes,format=der,type=private",
      dh_priv_der_serializer_functions },
    { "DH", "default=yes,format=der,type=public",
      dh_pub_der_serializer_functions },
    { "DH", "default=yes,format=der,type=parameters",
      dh_param_der_serializer_functions },
    { "DH", "default=yes,format=pem,type=private",
      dh_priv_pem_serializer_functions },
    { "DH", "default=yes,format=pem,type=public",
      dh_pub_pem_serializer_functions },
    { "DH", "default=yes,format=pem,type=parameters",
      dh_param_pem_serializer_functions },
#endif

#ifndef OPENSSL_NO_DSA
    { "DSA", "default=yes,format=text,type=private",
      dsa_priv_text_serializer_functions },
    { "DSA", "default=yes,format=text,type=public",
      dsa_pub_text_serializer_functions },
    { "DSA", "default=yes,format=text,type=parameters",
      dsa_param_text_serializer_functions },
    { "DSA", "default=yes,format=der,type=private",
      dsa_priv_der_serializer_functions },
    { "DSA", "default=yes,format=der,type=public",
      dsa_pub_der_serializer_functions },
    { "DSA", "default=yes,format=der,type=parameters",
      dsa_param_der_serializer_functions },
    { "DSA", "default=yes,format=pem,type=private",
      dsa_priv_pem_serializer_functions },
    { "DSA", "default=yes,format=pem,type=public",
      dsa_pub_pem_serializer_functions },
    { "DSA", "default=yes,format=pem,type=parameters",
      dsa_param_pem_serializer_functions },
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
        ossl_prov_cache_exported_algorithms(deflt_ciphers, exported_ciphers);
        return exported_ciphers;
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
    case OSSL_OP_ASYM_CIPHER:
        return deflt_asym_cipher;
    case OSSL_OP_SERIALIZER:
        return deflt_serializer;
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

    if (!ossl_prov_bio_from_dispatch(in))
        return 0;
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
