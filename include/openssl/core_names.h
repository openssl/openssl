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

/*
 * Well known parameter names that Providers can define
 */

/*
 * A printable name for this provider
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_NAME        "name"
/*
 * A version string for this provider
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_VERSION     "version"
/*
 * A string providing provider specific build information
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_BUILDINFO   "buildinfo"

/*
 * The module filename
 * Type: OSSL_PARAM_OCTET_STRING
 */
#define OSSL_PROV_PARAM_MODULE_FILENAME "module-filename"

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
#define OSSL_CIPHER_PARAM_PADDING   "padding"    /* uint */
#define OSSL_CIPHER_PARAM_MODE      "mode"       /* uint */
#define OSSL_CIPHER_PARAM_BLOCK_SIZE "blocksize" /* size_t */
#define OSSL_CIPHER_PARAM_FLAGS     "flags"      /* ulong */
#define OSSL_CIPHER_PARAM_KEYLEN    "keylen"     /* size_t */
#define OSSL_CIPHER_PARAM_IVLEN     "ivlen"      /* size_t */
#define OSSL_CIPHER_PARAM_IV        "iv"         /* octet_string OR octet_ptr */
#define OSSL_CIPHER_PARAM_NUM       "num"        /* uint */
#define OSSL_CIPHER_PARAM_ROUNDS    "rounds"     /* uint */
#define OSSL_CIPHER_PARAM_AEAD_TAG           "tag"        /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD      "tlsaad"     /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD  "tlsaadpad"  /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED "tlsivfixed" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_IVLEN         OSSL_CIPHER_PARAM_IVLEN
#define OSSL_CIPHER_PARAM_AEAD_TAGLEN        "taglen"     /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_MAC_KEY       "mackey"     /* octet_string */
#define OSSL_CIPHER_PARAM_RANDOM_KEY         "randkey"    /* octet_string */
#define OSSL_CIPHER_PARAM_RC2_KEYBITS        "keybits"    /* size_t */
#define OSSL_CIPHER_PARAM_SPEED              "speed"      /* uint */
/* For passing the AlgorithmIdentifier parameter in DER form */
#define OSSL_CIPHER_PARAM_ALG_ID             "alg_id_param" /* octet_string */


/* digest parameters */
#define OSSL_DIGEST_PARAM_XOFLEN     "xoflen"    /* size_t */
#define OSSL_DIGEST_PARAM_SSL3_MS    "ssl3-ms"   /* octet string */
#define OSSL_DIGEST_PARAM_PAD_TYPE   "pad_type"  /* uint */
#define OSSL_DIGEST_PARAM_MICALG     "micalg"    /* utf8 string */
#define OSSL_DIGEST_PARAM_BLOCK_SIZE "blocksize" /* size_t */
#define OSSL_DIGEST_PARAM_SIZE       "size"      /* size_t */
#define OSSL_DIGEST_PARAM_FLAGS      "flags"     /* ulong */

/* Known DIGEST names (not a complete list) */
#define OSSL_DIGEST_NAME_MD5 "MD5"
#define OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK_KMAC128"
#define OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK_KMAC256"

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
#define OSSL_KDF_NAME_SCRYPT        "id-scrypt"
#define OSSL_KDF_NAME_SSHKDF        "SSHKDF"
#define OSSL_KDF_NAME_SSKDF         "SSKDF"
#define OSSL_KDF_NAME_TLS1_PRF      "TLS1-PRF"
#define OSSL_KDF_NAME_X942KDF       "X942KDF"
#define OSSL_KDF_NAME_X963KDF       "X963KDF"
#define OSSL_KDF_NAME_KBKDF         "KBKDF"
#define OSSL_KDF_NAME_KRB5KDF       "KRB5KDF"

/* PKEY parameters */
/* Diffie-Hellman/DSA Parameters */
#define OSSL_PKEY_PARAM_FFC_P        "p"
#define OSSL_PKEY_PARAM_FFC_G        "g"
#define OSSL_PKEY_PARAM_FFC_Q        "q"

/* Diffie-Hellman Keys */
#define OSSL_PKEY_PARAM_DH_PUB_KEY   "pub"
#define OSSL_PKEY_PARAM_DH_PRIV_KEY  "priv"

/* DSA Keys */
#define OSSL_PKEY_PARAM_DSA_PUB_KEY  "pub"
#define OSSL_PKEY_PARAM_DSA_PRIV_KEY "priv"

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
#define OSSL_SIGNATURE_PARAM_DIGEST         "digest"
#define OSSL_SIGNATURE_PARAM_DIGEST_SIZE    "digest-size"

# ifdef __cplusplus
}
# endif

#endif
