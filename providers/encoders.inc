/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ENCODER_PROVIDER
# error Macro ENCODER_PROVIDER undefined
#endif
#define ENCODER_TEXT(name, _fips, func_table)                               \
    { name,                                                                 \
      "provider=" ENCODER_PROVIDER ",fips=" _fips ",output=text",           \
      (func_table) }
#define ENCODER(name, _fips, _output, _structure, func_table)               \
    { name,                                                                 \
      "provider=" ENCODER_PROVIDER ",fips=" _fips ",output=" _output        \
      ",structure=" _structure,                                             \
      (func_table) }

/*
 * Entries for human text "encoders"
 */
ENCODER_TEXT("RSA", "yes", ossl_rsa_to_text_encoder_functions),
ENCODER_TEXT("RSA-PSS", "yes", ossl_rsapss_to_text_encoder_functions),
#ifndef OPENSSL_NO_DH
ENCODER_TEXT("DH", "yes", ossl_dh_to_text_encoder_functions),
ENCODER_TEXT("DHX", "yes", ossl_dhx_to_text_encoder_functions),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER_TEXT("DSA", "yes", ossl_dsa_to_text_encoder_functions),
#endif
#ifndef OPENSSL_NO_EC
ENCODER_TEXT("EC", "yes", ossl_ec_to_text_encoder_functions),
ENCODER_TEXT("ED25519", "yes", ossl_ed25519_to_text_encoder_functions),
ENCODER_TEXT("ED448", "yes", ossl_ed448_to_text_encoder_functions),
ENCODER_TEXT("X25519", "yes", ossl_x25519_to_text_encoder_functions),
ENCODER_TEXT("X448", "yes", ossl_x448_to_text_encoder_functions),
#endif

/*
 * Entries to support i2d_PrivateKey(), i2d_PublicKey() and i2d_KeyParams()
 * They need a uniform structure name, we currently use "ossl".
 */
ENCODER("RSA", "yes", "der", "ossl",
        ossl_rsa_to_OSSL_old_der_encoder_functions),
ENCODER("RSA-PSS", "yes", "der", "ossl",
        ossl_rsapss_to_OSSL_current_der_encoder_functions),
#ifndef OPENSSL_NO_DH
ENCODER("DH", "yes", "der", "ossl",
        ossl_dh_to_OSSL_current_w_params_der_encoder_functions),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER("DSA", "yes", "der", "ossl",
        ossl_dsa_to_OSSL_old_w_params_der_encoder_functions),
#endif
#ifndef OPENSSL_NO_EC
ENCODER("EC", "yes", "der", "ossl",
        ossl_ec_to_OSSL_old_w_params_der_encoder_functions),
ENCODER("ED25519", "yes", "der", "ossl",
        ossl_ed25519_to_OSSL_current_der_encoder_functions),
ENCODER("ED448", "yes", "der", "ossl",
        ossl_ed448_to_OSSL_current_der_encoder_functions),
ENCODER("X25519", "yes", "der", "ossl",
        ossl_x25519_to_OSSL_current_der_encoder_functions),
ENCODER("X448", "yes", "der", "ossl",
        ossl_x448_to_OSSL_current_der_encoder_functions),
#endif

/*
 * Entries to support PEM_write_bio_Parameters(), using the same uniform
 * structure name "ossl".
 */
#ifndef OPENSSL_NO_DH
ENCODER("DH", "yes", "pem", "ossl", ossl_dh_to_OSSL_params_pem_encoder_functions),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER("DSA", "yes", "pem", "ossl", ossl_dsa_to_OSSL_params_pem_encoder_functions),
#endif
#ifndef OPENSSL_NO_EC
ENCODER("EC", "yes", "pem", "ossl", ossl_ec_to_OSSL_params_pem_encoder_functions),
#endif

/*
 * Entries for PKCS#8 and SubjectPublicKeyInfo.  These are added convenience
 * for any user that wants to use OSSL_ENCODER directly.  However, the "pem"
 * ones also support PEM_write_bio_PrivateKey() and PEM_write_bio_PUBKEY().
 */
ENCODER("RSA", "yes", "der", "pkcs8", ossl_rsa_to_PKCS8_der_encoder_functions),
ENCODER("RSA", "yes", "pem", "pkcs8", ossl_rsa_to_PKCS8_pem_encoder_functions),
ENCODER("RSA", "yes", "der", "SubjectPublicKeyInfo",
        ossl_rsa_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("RSA", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_rsa_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("RSA-PSS", "yes", "der", "pkcs8", ossl_rsapss_to_PKCS8_der_encoder_functions),
ENCODER("RSA-PSS", "yes", "pem", "pkcs8", ossl_rsapss_to_PKCS8_pem_encoder_functions),
ENCODER("RSA-PSS", "yes", "der", "SubjectPublicKeyInfo",
        ossl_rsapss_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("RSA-PSS", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_rsapss_to_SubjectPublicKeyInfo_pem_encoder_functions),

#ifndef OPENSSL_NO_DH
ENCODER("DH", "yes", "der", "pkcs8", ossl_dh_to_PKCS8_der_encoder_functions),
ENCODER("DH", "yes", "pem", "pkcs8", ossl_dh_to_PKCS8_pem_encoder_functions),
ENCODER("DH", "yes", "der", "SubjectPublicKeyInfo",
        ossl_dh_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("DH", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_dh_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("DHX", "yes", "der", "pkcs8", ossl_dhx_to_PKCS8_der_encoder_functions),
ENCODER("DHX", "yes", "pem", "pkcs8", ossl_dhx_to_PKCS8_pem_encoder_functions),
ENCODER("DHX", "yes", "der", "SubjectPublicKeyInfo",
        ossl_dhx_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("DHX", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_dhx_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_DSA
ENCODER("DSA", "yes", "der", "pkcs8", ossl_dsa_to_PKCS8_der_encoder_functions),
ENCODER("DSA", "yes", "pem", "pkcs8", ossl_dsa_to_PKCS8_pem_encoder_functions),
ENCODER("DSA", "yes", "der", "SubjectPublicKeyInfo",
        ossl_dsa_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("DSA", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_dsa_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_EC
ENCODER("EC", "yes", "der", "pkcs8", ossl_ec_to_PKCS8_der_encoder_functions),
ENCODER("EC", "yes", "pem", "pkcs8", ossl_ec_to_PKCS8_pem_encoder_functions),
ENCODER("EC", "yes", "der", "SubjectPublicKeyInfo",
        ossl_ec_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("EC", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_ec_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("X25519", "yes", "der", "pkcs8", ossl_x25519_to_PKCS8_der_encoder_functions),
ENCODER("X25519", "yes", "pem", "pkcs8", ossl_x25519_to_PKCS8_pem_encoder_functions),
ENCODER("X25519", "yes", "der", "SubjectPublicKeyInfo",
        ossl_x25519_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("X25519", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_x25519_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("X448", "yes", "der", "pkcs8", ossl_x448_to_PKCS8_der_encoder_functions),
ENCODER("X448", "yes", "pem", "pkcs8", ossl_x448_to_PKCS8_pem_encoder_functions),
ENCODER("X448", "yes", "der", "SubjectPublicKeyInfo",
        ossl_x448_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("X448", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_x448_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("ED25519", "yes", "der", "pkcs8", ossl_ed25519_to_PKCS8_der_encoder_functions),
ENCODER("ED25519", "yes", "pem", "pkcs8", ossl_ed25519_to_PKCS8_pem_encoder_functions),
ENCODER("ED25519", "yes", "der", "SubjectPublicKeyInfo",
        ossl_ed25519_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("ED25519", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_ed25519_to_SubjectPublicKeyInfo_pem_encoder_functions),

ENCODER("ED448", "yes", "der", "pkcs8", ossl_ed448_to_PKCS8_der_encoder_functions),
ENCODER("ED448", "yes", "pem", "pkcs8", ossl_ed448_to_PKCS8_pem_encoder_functions),
ENCODER("ED448", "yes", "der", "SubjectPublicKeyInfo",
        ossl_ed448_to_SubjectPublicKeyInfo_der_encoder_functions),
ENCODER("ED448", "yes", "pem", "SubjectPublicKeyInfo",
        ossl_ed448_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif

/*
 * Entries for key specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_by_EVP_PKEY(pkey, "DER", selection, NULL,
 *                                      "structure={type}");
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_by_EVP_PKEY(pkey, "PEM", selection, NULL,
 *                                      "structure={type}");
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */

/* The RSA encoders only support private key and public key output */
ENCODER("RSA", "yes", "der", "rsa", ossl_rsa_to_PKCS1_der_encoder_functions),
ENCODER("RSA", "yes", "pem", "rsa", ossl_rsa_to_PKCS1_pem_encoder_functions),
#ifndef OPENSSL_NO_DH
/* DH and X9.42 DH only support key parameters output. */
ENCODER("DH", "yes", "der", "dh", ossl_dh_to_PKCS3_der_encoder_functions),
ENCODER("DH", "yes", "pem", "dh", ossl_dh_to_PKCS3_pem_encoder_functions),
ENCODER("DHX", "yes", "der", "dhx", ossl_dhx_to_X9_42_der_encoder_functions),
ENCODER("DHX", "yes", "pem", "dhx", ossl_dhx_to_X9_42_pem_encoder_functions),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER("DSA", "yes", "der", "dsa", ossl_dsa_to_RAW_w_params_der_encoder_functions),
ENCODER("DSA", "yes", "pem", "dsa", ossl_dsa_to_RAW_w_params_pem_encoder_functions),
#endif
#ifndef OPENSSL_NO_EC
ENCODER("EC", "yes", "der", "ec", ossl_ec_to_RAW_w_params_der_encoder_functions),
ENCODER("EC", "yes", "pem", "ec", ossl_ec_to_RAW_w_params_pem_encoder_functions),
#endif

/*
 * Additional entries with structure names being the standard name.
 * This is entirely for the convenience of the user that wants to use
 * OSSL_ENCODER directly with names they may fancy.  These do not impact
 * on libcrypto functionality in any way.
 */
/* PKCS#1 is a well known for plain RSA keys, so we add that too */
ENCODER("RSA", "yes", "der", "pkcs1", ossl_rsa_to_PKCS1_der_encoder_functions),
ENCODER("RSA", "yes", "pem", "pkcs1", ossl_rsa_to_PKCS1_pem_encoder_functions),
#ifndef OPENSSL_NO_DH
/* PKCS#3 defines the format for DH parameters */
ENCODER("DH", "yes", "der", "pkcs3", ossl_dh_to_PKCS3_der_encoder_functions),
ENCODER("DH", "yes", "pem", "pkcs3", ossl_dh_to_PKCS3_pem_encoder_functions),
/* X9.42 defines the format for DHX parameters */
ENCODER("DHX", "yes", "der", "X9.42", ossl_dhx_to_X9_42_der_encoder_functions),
ENCODER("DHX", "yes", "pem", "X9.42", ossl_dhx_to_X9_42_pem_encoder_functions),
#endif
