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

#define ENCODER_STRUCTURE_type_specific_keypair         "type-specific"
#define ENCODER_STRUCTURE_type_specific_params          "type-specific"
#define ENCODER_STRUCTURE_type_specific                 "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub          "type-specific"
#define ENCODER_STRUCTURE_PKCS8                         "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo          "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_DH                            "dh"
#define ENCODER_STRUCTURE_DHX                           "dhx"
#define ENCODER_STRUCTURE_DSA                           "dsa"
#define ENCODER_STRUCTURE_EC                            "ec"
#define ENCODER_STRUCTURE_RSA                           "rsa"
#define ENCODER_STRUCTURE_PKCS1                         "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                         "pkcs3"
#define ENCODER_STRUCTURE_X9_42                         "X9.42"
#define ENCODER_STRUCTURE_X9_62                         "X9.62"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym, _fips)                                \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",fips=" #_fips ",output=text",      \
      (ossl_##_sym##_to_text_encoder_functions) }
#define ENCODER(_name, _sym, _fips, _output, _structure)                \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",fips=" #_fips ",output=" #_output  \
      ",structure=" ENCODER_STRUCTURE_##_structure,                     \
      (ossl_##_sym##_to_##_structure##_##_output##_encoder_functions) }

/*
 * Entries for human text "encoders"
 */
ENCODER_TEXT("RSA", rsa, yes),
ENCODER_TEXT("RSA-PSS", rsapss, yes),
#ifndef OPENSSL_NO_DH
ENCODER_TEXT("DH", dh, yes),
ENCODER_TEXT("DHX", dhx, yes),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER_TEXT("DSA", dsa, yes),
#endif
#ifndef OPENSSL_NO_EC
ENCODER_TEXT("EC", ec, yes),
ENCODER_TEXT("ED25519", ed25519, yes),
ENCODER_TEXT("ED448", ed448, yes),
ENCODER_TEXT("X25519", x25519, yes),
ENCODER_TEXT("X448", x448, yes),
#endif

/*
 * Entries for key type specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_by_EVP_PKEY(pkey, selection, "DER", "type-specific",
 *                                      NULL, NULL);
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_by_EVP_PKEY(pkey, selection, "PEM", "type-specific",
 *                                      NULL, NULL);
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */

/* The RSA encoders only support private key and public key output */
ENCODER("RSA", rsa, yes, der, type_specific_keypair),
ENCODER("RSA", rsa, yes, pem, type_specific_keypair),
#ifndef OPENSSL_NO_DH
/* DH and X9.42 DH only support key parameters output. */
ENCODER("DH", dh, yes, der, type_specific_params),
ENCODER("DH", dh, yes, pem, type_specific_params),
ENCODER("DHX", dhx, yes, der, type_specific_params),
ENCODER("DHX", dhx, yes, pem, type_specific_params),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER("DSA", dsa, yes, der, type_specific),
ENCODER("DSA", dsa, yes, pem, type_specific),
#endif
#ifndef OPENSSL_NO_EC
/* EC only supports keypair and parameters output. */
ENCODER("EC", ec, yes, der, type_specific_no_pub),
ENCODER("EC", ec, yes, pem, type_specific_no_pub),
#endif

/*
 * Entries for PKCS#8 and SubjectPublicKeyInfo.
 * The "der" ones are added convenience for any user that wants to use
 * OSSL_ENCODER directly.
 * The "pem" ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 */
ENCODER("RSA", rsa, yes, der, PKCS8),
ENCODER("RSA", rsa, yes, pem, PKCS8),
ENCODER("RSA", rsa, yes, der, SubjectPublicKeyInfo),
ENCODER("RSA", rsa, yes, pem, SubjectPublicKeyInfo),

ENCODER("RSA-PSS", rsapss, yes, der, PKCS8),
ENCODER("RSA-PSS", rsapss, yes, pem, PKCS8),
ENCODER("RSA-PSS", rsapss, yes, der, SubjectPublicKeyInfo),
ENCODER("RSA-PSS", rsapss, yes, pem, SubjectPublicKeyInfo),

#ifndef OPENSSL_NO_DH
ENCODER("DH", dh, yes, der, PKCS8),
ENCODER("DH", dh, yes, pem, PKCS8),
ENCODER("DH", dh, yes, der, SubjectPublicKeyInfo),
ENCODER("DH", dh, yes, pem, SubjectPublicKeyInfo),

ENCODER("DHX", dhx, yes, der, PKCS8),
ENCODER("DHX", dhx, yes, pem, PKCS8),
ENCODER("DHX", dhx, yes, der, SubjectPublicKeyInfo),
ENCODER("DHX", dhx, yes, pem, SubjectPublicKeyInfo),
#endif

#ifndef OPENSSL_NO_DSA
ENCODER("DSA", dsa, yes, der, PKCS8),
ENCODER("DSA", dsa, yes, pem, PKCS8),
ENCODER("DSA", dsa, yes, der, SubjectPublicKeyInfo),
ENCODER("DSA", dsa, yes, pem, SubjectPublicKeyInfo),
#endif

#ifndef OPENSSL_NO_EC
ENCODER("EC", ec, yes, der, PKCS8),
ENCODER("EC", ec, yes, pem, PKCS8),
ENCODER("EC", ec, yes, der, SubjectPublicKeyInfo),
ENCODER("EC", ec, yes, pem, SubjectPublicKeyInfo),

ENCODER("X25519", x25519, yes, der, PKCS8),
ENCODER("X25519", x25519, yes, pem, PKCS8),
ENCODER("X25519", x25519, yes, der, SubjectPublicKeyInfo),
ENCODER("X25519", x25519, yes, pem, SubjectPublicKeyInfo),

ENCODER("X448", x448, yes, der, PKCS8),
ENCODER("X448", x448, yes, pem, PKCS8),
ENCODER("X448", x448, yes, der, SubjectPublicKeyInfo),
ENCODER("X448", x448, yes, pem, SubjectPublicKeyInfo),

ENCODER("ED25519", ed25519, yes, der, PKCS8),
ENCODER("ED25519", ed25519, yes, pem, PKCS8),
ENCODER("ED25519", ed25519, yes, der, SubjectPublicKeyInfo),
ENCODER("ED25519", ed25519, yes, pem, SubjectPublicKeyInfo),

ENCODER("ED448", ed448, yes, der, PKCS8),
ENCODER("ED448", ed448, yes, pem, PKCS8),
ENCODER("ED448", ed448, yes, der, SubjectPublicKeyInfo),
ENCODER("ED448", ed448, yes, pem, SubjectPublicKeyInfo),
#endif

/*
 * Entries for key type specific output formats.  These are exactly the
 * same as the type specific above, except that they use the key type
 * name as structure name instead of "type-specific", in the call on
 * OSSL_ENCODER_CTX_new_by_EVP_PKEY().
 */

/* The RSA encoders only support private key and public key output */
ENCODER("RSA", rsa, yes, der, RSA),
ENCODER("RSA", rsa, yes, pem, RSA),
#ifndef OPENSSL_NO_DH
/* DH and X9.42 DH only support key parameters output. */
ENCODER("DH", dh, yes, der, DH),
ENCODER("DH", dh, yes, pem, DH),
ENCODER("DHX", dhx, yes, der, DHX),
ENCODER("DHX", dhx, yes, pem, DHX),
#endif
#ifndef OPENSSL_NO_DSA
ENCODER("DSA", dsa, yes, der, DSA),
ENCODER("DSA", dsa, yes, pem, DSA),
#endif
#ifndef OPENSSL_NO_EC
ENCODER("EC", ec, yes, der, EC),
ENCODER("EC", ec, yes, pem, EC),
#endif

/*
 * Additional entries with structure names being the standard name.
 * This is entirely for the convenience of the user that wants to use
 * OSSL_ENCODER directly with names they may fancy.  These do not impact
 * on libcrypto functionality in any way.
 */
/* PKCS#1 is a well known for plain RSA keys, so we add that too */
ENCODER("RSA", rsa, yes, der, PKCS1),
ENCODER("RSA", rsa, yes, pem, PKCS1),
ENCODER("RSA-PSS", rsapss, yes, der, PKCS1),
ENCODER("RSA-PSS", rsapss, yes, pem, PKCS1),
#ifndef OPENSSL_NO_DH
/* PKCS#3 defines the format for DH parameters */
ENCODER("DH", dh, yes, der, PKCS3),
ENCODER("DH", dh, yes, pem, PKCS3),
/* X9.42 defines the format for DHX parameters */
ENCODER("DHX", dhx, yes, der, X9_42),
ENCODER("DHX", dhx, yes, pem, X9_42),
#endif
#ifndef OPENSSL_NO_EC
/* RFC 5915 defines the format for EC keys and parameters */
ENCODER("EC", ec, yes, der, X9_62),
ENCODER("EC", ec, yes, pem, X9_62),
#endif
