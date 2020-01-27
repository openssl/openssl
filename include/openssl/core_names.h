/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CORE_NAMES_H
# define OPENSSL_CORE_NAMES_H

# ifdef __cplusplus
extern "C" {
# endif

/* Well known parameter names that Providers can define */
#define OSSL_PROV_PARAM_NAME            "name"                /* utf8_string */
#define OSSL_PROV_PARAM_VERSION         "version"             /* utf8_string */
#define OSSL_PROV_PARAM_BUILDINFO       "buildinfo"           /* utf8_string */
#define OSSL_PROV_PARAM_MODULE_FILENAME "module-filename"     /* octet_string */

/* Self test callback parameters */
#define OSSL_PROV_PARAM_SELF_TEST_PHASE  "st-phase" /* utf8_string */
#define OSSL_PROV_PARAM_SELF_TEST_TYPE   "st-type"  /* utf8_string */
#define OSSL_PROV_PARAM_SELF_TEST_DESC   "st-desc"  /* utf8_string */

/*
 * Algorithm parameters
 * If "engine" or "properties" are specified, they should always be paired
 * with the algorithm type.
 */
#define OSSL_ALG_PARAM_DIGEST       "digest"    /* utf8_string */
#define OSSL_ALG_PARAM_CIPHER       "cipher"    /* utf8_string */
#define OSSL_ALG_PARAM_MAC          "mac"       /* utf8_string */
#define OSSL_ALG_PARAM_PROPERTIES   "properties"/* utf8_string */

/* cipher parameters */
#define OSSL_CIPHER_PARAM_PADDING              "padding"    /* uint */
#define OSSL_CIPHER_PARAM_MODE                 "mode"       /* uint */
#define OSSL_CIPHER_PARAM_BLOCK_SIZE           "blocksize" /* size_t */
#define OSSL_CIPHER_PARAM_FLAGS                "flags"      /* ulong */
#define OSSL_CIPHER_PARAM_KEYLEN               "keylen"     /* size_t */
#define OSSL_CIPHER_PARAM_IVLEN                "ivlen"      /* size_t */
#define OSSL_CIPHER_PARAM_IV                   "iv"         /* octet_string OR octet_ptr */
#define OSSL_CIPHER_PARAM_NUM                  "num"        /* uint */
#define OSSL_CIPHER_PARAM_ROUNDS               "rounds"     /* uint */
#define OSSL_CIPHER_PARAM_AEAD_TAG             "tag"        /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD        "tlsaad"     /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD    "tlsaadpad"  /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED   "tlsivfixed" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN "tlsivgen" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV "tlsivinv" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_IVLEN           OSSL_CIPHER_PARAM_IVLEN
#define OSSL_CIPHER_PARAM_AEAD_TAGLEN          "taglen"     /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_MAC_KEY         "mackey"     /* octet_string */
#define OSSL_CIPHER_PARAM_RANDOM_KEY           "randkey"    /* octet_string */
#define OSSL_CIPHER_PARAM_RC2_KEYBITS          "keybits"    /* size_t */
#define OSSL_CIPHER_PARAM_SPEED                "speed"      /* uint */
/* For passing the AlgorithmIdentifier parameter in DER form */
#define OSSL_CIPHER_PARAM_ALG_ID               "alg_id_param" /* octet_string */

#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT                    \
    "tls1multi_maxsndfrag" /* uint */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE                          \
    "tls1multi_maxbufsz"   /* size_t */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE                           \
    "tls1multi_interleave" /* uint */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD                                  \
    "tls1multi_aad"        /* octet_string */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN                          \
    "tls1multi_aadpacklen" /* uint */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC                                  \
    "tls1multi_enc"        /* octet_string */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN                               \
    "tls1multi_encin"      /* octet_string */
#define OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN                              \
    "tls1multi_enclen"     /* size_t */

/* digest parameters */
#define OSSL_DIGEST_PARAM_XOFLEN     "xoflen"    /* size_t */
#define OSSL_DIGEST_PARAM_SSL3_MS    "ssl3-ms"   /* octet string */
#define OSSL_DIGEST_PARAM_PAD_TYPE   "pad_type"  /* uint */
#define OSSL_DIGEST_PARAM_MICALG     "micalg"    /* utf8 string */
#define OSSL_DIGEST_PARAM_BLOCK_SIZE "blocksize" /* size_t */
#define OSSL_DIGEST_PARAM_SIZE       "size"      /* size_t */
#define OSSL_DIGEST_PARAM_FLAGS      "flags"     /* ulong */

/* Known DIGEST names (not a complete list) */
#define OSSL_DIGEST_NAME_MD5            "MD5"
#define OSSL_DIGEST_NAME_SHA1           "SHA1"
#define OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
#define OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
#define OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
#define OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
#define OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
#define OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
#define OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
#define OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
#define OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK-KMAC-128"
#define OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK-KMAC-256"

/* MAC parameters */
#define OSSL_MAC_PARAM_KEY          "key"        /* octet string */
#define OSSL_MAC_PARAM_IV           "iv"         /* octet string */
#define OSSL_MAC_PARAM_CUSTOM       "custom"     /* utf8 string */
#define OSSL_MAC_PARAM_SALT         "salt"       /* octet string */
#define OSSL_MAC_PARAM_XOF          "xof"        /* int, 0 or 1 */
#define OSSL_MAC_PARAM_FLAGS        "flags"      /* int */
/*
 * If "engine" or "properties" are specified, they should always be paired
 * with "cipher" or "digest".
 */
#define OSSL_MAC_PARAM_CIPHER       OSSL_ALG_PARAM_CIPHER     /* utf8 string */
#define OSSL_MAC_PARAM_DIGEST       OSSL_ALG_PARAM_DIGEST     /* utf8 string */
#define OSSL_MAC_PARAM_PROPERTIES   OSSL_ALG_PARAM_PROPERTIES /* utf8 string */
#define OSSL_MAC_PARAM_SIZE         "size"       /* size_t */

/* Known MAC names (not a complete list) */
#define OSSL_MAC_NAME_CMAC          "CMAC"
#define OSSL_MAC_NAME_HMAC          "HMAC"
#define OSSL_MAC_NAME_KMAC128       "KMAC128"
#define OSSL_MAC_NAME_KMAC256       "KMAC256"

/* KDF / PRF parameters */
#define OSSL_KDF_PARAM_SECRET       "secret"    /* octet string */
#define OSSL_KDF_PARAM_KEY          "key"       /* octet string */
#define OSSL_KDF_PARAM_SALT         "salt"      /* octet string */
#define OSSL_KDF_PARAM_PASSWORD     "pass"      /* octet string */
#define OSSL_KDF_PARAM_DIGEST       OSSL_ALG_PARAM_DIGEST     /* utf8 string */
#define OSSL_KDF_PARAM_CIPHER       OSSL_ALG_PARAM_CIPHER     /* utf8 string */
#define OSSL_KDF_PARAM_MAC          OSSL_ALG_PARAM_MAC        /* utf8 string */
#define OSSL_KDF_PARAM_MAC_SIZE     "maclen"    /* size_t */
#define OSSL_KDF_PARAM_PROPERTIES   OSSL_ALG_PARAM_PROPERTIES /* utf8 string */
#define OSSL_KDF_PARAM_ITER         "iter"      /* unsigned int */
#define OSSL_KDF_PARAM_MODE         "mode"      /* utf8 string or int */
#define OSSL_KDF_PARAM_PKCS5        "pkcs5"     /* int */
#define OSSL_KDF_PARAM_UKM          "ukm"       /* octet string */
#define OSSL_KDF_PARAM_CEK_ALG      "cekalg"    /* utf8 string */
#define OSSL_KDF_PARAM_SCRYPT_N     "n"         /* uint64_t */
#define OSSL_KDF_PARAM_SCRYPT_R     "r"         /* uint32_t */
#define OSSL_KDF_PARAM_SCRYPT_P     "p"         /* uint32_t */
#define OSSL_KDF_PARAM_SCRYPT_MAXMEM "maxmem_bytes" /* uint64_t */
#define OSSL_KDF_PARAM_INFO         "info"      /* octet string */
#define OSSL_KDF_PARAM_SEED         "seed"      /* octet string */
#define OSSL_KDF_PARAM_SSHKDF_XCGHASH "xcghash" /* octet string */
#define OSSL_KDF_PARAM_SSHKDF_SESSION_ID "session_id" /* octet string */
#define OSSL_KDF_PARAM_SSHKDF_TYPE  "type"      /* int */
#define OSSL_KDF_PARAM_SIZE         "size"      /* size_t */
#define OSSL_KDF_PARAM_CIPHER       OSSL_ALG_PARAM_CIPHER     /* utf8 string */
#define OSSL_KDF_PARAM_CONSTANT     "constant"  /* octet string */

/* Known KDF names */
#define OSSL_KDF_NAME_HKDF          "HKDF"
#define OSSL_KDF_NAME_PBKDF2        "PBKDF2"
#define OSSL_KDF_NAME_SCRYPT        "SCRYPT"
#define OSSL_KDF_NAME_SSHKDF        "SSHKDF"
#define OSSL_KDF_NAME_SSKDF         "SSKDF"
#define OSSL_KDF_NAME_TLS1_PRF      "TLS1-PRF"
#define OSSL_KDF_NAME_X942KDF       "X942KDF"
#define OSSL_KDF_NAME_X963KDF       "X963KDF"
#define OSSL_KDF_NAME_KBKDF         "KBKDF"
#define OSSL_KDF_NAME_KRB5KDF       "KRB5KDF"

/* PKEY parameters */
/* Common PKEY parameters */
#define OSSL_PKEY_PARAM_BITS                "bits" /* integer */
#define OSSL_PKEY_PARAM_MAX_SIZE            "max-size" /* integer */
#define OSSL_PKEY_PARAM_SECURITY_BITS       "security-bits" /* integer */
#define OSSL_PKEY_PARAM_DIGEST              OSSL_ALG_PARAM_DIGEST
#define OSSL_PKEY_PARAM_PROPERTIES          OSSL_ALG_PARAM_PROPERTIES
#define OSSL_PKEY_PARAM_DEFAULT_DIGEST      "default-digest" /* utf8 string */
#define OSSL_PKEY_PARAM_MANDATORY_DIGEST    "mandatory-digest" /* utf8 string */
#define OSSL_PKEY_PARAM_PUB_KEY             "pub"
#define OSSL_PKEY_PARAM_PRIV_KEY            "priv"

/* Diffie-Hellman/DSA Parameters */
#define OSSL_PKEY_PARAM_FFC_P        "p"
#define OSSL_PKEY_PARAM_FFC_G        "g"
#define OSSL_PKEY_PARAM_FFC_Q        "q"

/* RSA Keys */
/*
 * n, e, d are the usual public and private key components
 *
 * rsa-num is the number of factors, including p and q
 * rsa-factor is used for each factor: p, q, r_i (i = 3, ...)
 * rsa-exponent is used for each exponent: dP, dQ, d_i (i = 3, ...)
 * rsa-coefficient is used for each coefficient: qInv, t_i (i = 3, ...)
 *
 * The number of rsa-factor items must be equal to the number of rsa-exponent
 * items, and the number of rsa-coefficients must be one less.
 * (the base i for the coefficients is 2, not 1, at least as implied by
 * RFC 8017)
 */
#define OSSL_PKEY_PARAM_RSA_N           "n"
#define OSSL_PKEY_PARAM_RSA_E           "e"
#define OSSL_PKEY_PARAM_RSA_D           "d"
#define OSSL_PKEY_PARAM_RSA_FACTOR      "rsa-factor"
#define OSSL_PKEY_PARAM_RSA_EXPONENT    "rsa-exponent"
#define OSSL_PKEY_PARAM_RSA_COEFFICIENT "rsa-coefficient"

/* Key Exchange parameters */

#define OSSL_EXCHANGE_PARAM_PAD      "pad" /* uint */

/* Signature parameters */
#define OSSL_SIGNATURE_PARAM_ALGORITHM_ID       "algorithm-id"
#define OSSL_SIGNATURE_PARAM_DIGEST             OSSL_PKEY_PARAM_DIGEST
#define OSSL_SIGNATURE_PARAM_PROPERTIES         OSSL_PKEY_PARAM_PROPERTIES

/* Asym cipher parameters */
#define OSSL_ASYM_CIPHER_PARAM_PAD_MODE                 "pad-mode"
#define OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST              OSSL_ALG_PARAM_DIGEST
#define OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS        "digest-props"
#define OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST              "mgf1-digest"
#define OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS        "mgf1-digest-props"
#define OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL               "oaep-label"
#define OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL_LEN           "oaep-label-len"
#define OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION       "tls-client-version"
#define OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION   "tls-negotiated-version"

/*
 * Serializer parameters
 */
/* The passphrase may be passed as a utf8 string or an octet string */
#define OSSL_SERIALIZER_PARAM_CIPHER            OSSL_ALG_PARAM_CIPHER
#define OSSL_SERIALIZER_PARAM_PROPERTIES        OSSL_ALG_PARAM_PROPERTIES
#define OSSL_SERIALIZER_PARAM_PASS              "passphrase"

/* Passphrase callback parameters */
#define OSSL_PASSPHRASE_PARAM_INFO              "info"

# ifdef __cplusplus
}
# endif

#endif
