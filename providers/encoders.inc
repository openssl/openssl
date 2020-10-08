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
     * All key TYPEs that have i2d_TYPEPrivateKey, i2d_TYPEPublicKey and
     * i2d_TYPEparams functions should have a corresponding "raw" entry
     * here.  They implement the structure that is relevant for the key
     * TYPE (RSA does PKCS#1, DH does PKCS#3, ...)
     *
     * All key types that have old_encode_priv implementation in the
     * EVP_PKEY_ASN1_METHOD should have a corresponding "rawkey" entry
     * here.
     *
     * All key types should have "pkcs8" and "SubjectPublicKeyInfo"
     * entries here.
     *
     * There may be additional entries with other structure names for the
     * convenience of the users.
     */

    ENCODER_TEXT("RSA", "yes", ossl_rsa_to_text_encoder_functions),
    ENCODER("RSA", "yes", "der", "raw",
            ossl_rsa_to_RAW_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", "raw",
            ossl_rsa_to_RAW_pem_encoder_functions),
    ENCODER("RSA", "yes", "der", "rawkey",
            ossl_rsa_to_RAWKEY_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", "rawkey",
            ossl_rsa_to_RAWKEY_pem_encoder_functions),
    ENCODER("RSA", "yes", "der", "pkcs8",
            ossl_rsa_to_PKCS8_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", "pkcs8",
            ossl_rsa_to_PKCS8_pem_encoder_functions),
    ENCODER("RSA", "yes", "der", "SubjectPublicKeyInfo",
            ossl_rsa_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_rsa_to_SubjectPublicKeyInfo_pem_encoder_functions),
    /* PKCS#1 is a well known for plain RSA keys, so we add that too */
    ENCODER("RSA", "yes", "der", "pkcs1",
            ossl_rsa_to_RAW_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", "pkcs1",
            ossl_rsa_to_RAW_pem_encoder_functions),

    /*
     * RSA-PSS uses the same functions as RSA, except for RAW, PKCS#8
     * and SubjectPublicKeyInfo
     */
    ENCODER_TEXT("RSA-PSS", "yes", ossl_rsapss_to_text_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", "raw",
            ossl_rsapss_to_RAW_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", "raw",
            ossl_rsapss_to_RAW_pem_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", "rawkey",
            ossl_rsa_to_RAWKEY_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", "rawkey",
            ossl_rsa_to_RAWKEY_pem_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", "pkcs8",
            ossl_rsapss_to_PKCS8_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", "pkcs8",
            ossl_rsapss_to_PKCS8_pem_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", "SubjectPublicKeyInfo",
            ossl_rsapss_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_rsapss_to_SubjectPublicKeyInfo_pem_encoder_functions),

#ifndef OPENSSL_NO_DH
    /*
     * OpenSSL 1.1.1 DH EVP_PKEY_ASN1_METHOD doesn't implement old_priv_encode,
     * So we provide no "rawkey" implementation.
     */
    ENCODER_TEXT("DH", "yes", ossl_dh_to_text_encoder_functions),
    ENCODER("DH", "yes", "der", "raw",
            ossl_dh_to_RAW_der_encoder_functions),
    ENCODER("DH", "yes", "pem", "raw",
            ossl_dh_to_RAW_pem_encoder_functions),
    ENCODER("DH", "yes", "der", "pkcs8",
            ossl_dh_to_PKCS8_der_encoder_functions),
    ENCODER("DH", "yes", "pem", "pkcs8",
            ossl_dh_to_PKCS8_pem_encoder_functions),
    ENCODER("DH", "yes", "der", "SubjectPublicKeyInfo",
            ossl_dh_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("DH", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_dh_to_SubjectPublicKeyInfo_pem_encoder_functions),

    ENCODER_TEXT("DHX", "yes", ossl_dhx_to_text_encoder_functions),
    ENCODER("DHX", "yes", "der", "raw",
            ossl_dhx_to_RAW_der_encoder_functions),
    ENCODER("DHX", "yes", "pem", "raw",
            ossl_dhx_to_RAW_pem_encoder_functions),
    ENCODER("DHX", "yes", "der", "pkcs8",
            ossl_dhx_to_PKCS8_der_encoder_functions),
    ENCODER("DHX", "yes", "pem", "pkcs8",
            ossl_dhx_to_PKCS8_pem_encoder_functions),
    ENCODER("DHX", "yes", "der", "SubjectPublicKeyInfo",
            ossl_dhx_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("DHX", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_dhx_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_DSA
    ENCODER_TEXT("DSA", "yes", ossl_dsa_to_text_encoder_functions),
    ENCODER("DSA", "yes", "der", "raw",
            ossl_dsa_to_RAW_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", "raw",
            ossl_dsa_to_RAW_pem_encoder_functions),
    ENCODER("DSA", "yes", "der", "rawkey",
            ossl_dsa_to_RAWKEY_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", "rawkey",
            ossl_dsa_to_RAWKEY_pem_encoder_functions),
    ENCODER("DSA", "yes", "der", "pkcs8",
            ossl_dsa_to_PKCS8_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", "pkcs8",
            ossl_dsa_to_PKCS8_pem_encoder_functions),
    ENCODER("DSA", "yes", "der", "SubjectPublicKeyInfo",
            ossl_dsa_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_dsa_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_EC
    /* X25519, X448, ED25519 and ED448 only support PKCS#8 and SPKI */
    ENCODER_TEXT("X25519", "yes", ossl_x25519_to_text_encoder_functions),
    ENCODER("X25519", "yes", "der", "pkcs8",
            ossl_x25519_to_PKCS8_der_encoder_functions),
    ENCODER("X25519", "yes", "pem", "pkcs8",
            ossl_x25519_to_PKCS8_pem_encoder_functions),
    ENCODER("X25519", "yes", "der", "SubjectPublicKeyInfo",
            ossl_x25519_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("X25519", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_x25519_to_SubjectPublicKeyInfo_pem_encoder_functions),

    ENCODER_TEXT("X448", "yes", ossl_x448_to_text_encoder_functions),
    ENCODER("X448", "yes", "der", "pkcs8",
            ossl_x448_to_PKCS8_der_encoder_functions),
    ENCODER("X448", "yes", "pem", "pkcs8",
            ossl_x448_to_PKCS8_pem_encoder_functions),
    ENCODER("X448", "yes", "der", "SubjectPublicKeyInfo",
            ossl_x448_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("X448", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_x448_to_SubjectPublicKeyInfo_pem_encoder_functions),

    ENCODER_TEXT("ED25519", "yes", ossl_ed25519_to_text_encoder_functions),
    ENCODER("ED25519", "yes", "der", "pkcs8",
            ossl_ed25519_to_PKCS8_der_encoder_functions),
    ENCODER("ED25519", "yes", "pem", "pkcs8",
            ossl_ed25519_to_PKCS8_pem_encoder_functions),
    ENCODER("ED25519", "yes", "der", "SubjectPublicKeyInfo",
            ossl_ed25519_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("ED25519", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_ed25519_to_SubjectPublicKeyInfo_pem_encoder_functions),

    ENCODER_TEXT("ED448", "yes", ossl_ed448_to_text_encoder_functions),
    ENCODER("ED448", "yes", "der", "pkcs8",
            ossl_ed448_to_PKCS8_der_encoder_functions),
    ENCODER("ED448", "yes", "pem", "pkcs8",
            ossl_ed448_to_PKCS8_pem_encoder_functions),
    ENCODER("ED448", "yes", "der", "SubjectPublicKeyInfo",
            ossl_ed448_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("ED448", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_ed448_to_SubjectPublicKeyInfo_pem_encoder_functions),

    ENCODER_TEXT("EC", "yes", ossl_ec_to_text_encoder_functions),
    ENCODER("EC", "yes", "der", "raw",
            ossl_ec_to_RAW_der_encoder_functions),
    ENCODER("EC", "yes", "pem", "raw",
            ossl_ec_to_RAW_pem_encoder_functions),
    ENCODER("EC", "yes", "der", "rawkey",
            ossl_ec_to_RAWKEY_der_encoder_functions),
    ENCODER("EC", "yes", "pem", "rawkey",
            ossl_ec_to_RAWKEY_pem_encoder_functions),
    ENCODER("EC", "yes", "der", "pkcs8",
            ossl_ec_to_PKCS8_der_encoder_functions),
    ENCODER("EC", "yes", "pem", "pkcs8",
            ossl_ec_to_PKCS8_pem_encoder_functions),
    ENCODER("EC", "yes", "der", "SubjectPublicKeyInfo",
            ossl_ec_to_SubjectPublicKeyInfo_der_encoder_functions),
    ENCODER("EC", "yes", "pem", "SubjectPublicKeyInfo",
            ossl_ec_to_SubjectPublicKeyInfo_pem_encoder_functions),
#endif
