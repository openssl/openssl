/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_NAMES_H
# define OSSL_CORE_NAMES_H

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

/* cipher parameters */
#define OSSL_CIPHER_PARAM_PADDING   "padding"    /* uint */
#define OSSL_CIPHER_PARAM_MODE      "mode"       /* uint */
#define OSSL_CIPHER_PARAM_BLOCK_SIZE "blocksize" /* size_t */
#define OSSL_CIPHER_PARAM_FLAGS     "flags"      /* ulong */
#define OSSL_CIPHER_PARAM_KEYLEN    "keylen"     /* size_t */
#define OSSL_CIPHER_PARAM_IVLEN     "ivlen"      /* size_t */
#define OSSL_CIPHER_PARAM_IV        "iv"         /* octet_string OR octet_ptr */
#define OSSL_CIPHER_PARAM_NUM       "num"        /* uint */
#define OSSL_CIPHER_PARAM_AEAD_TAG           "tag"        /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD      "tlsaad"     /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD  "tlsaadpad"  /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED "tlsivfixed" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_IVLEN OSSL_CIPHER_PARAM_IVLEN
#define OSSL_CIPHER_PARAM_RANDOM_KEY         "randkey"    /* octet_string */

/* digest parameters */
#define OSSL_DIGEST_PARAM_XOFLEN     "xoflen"    /* size_t */
#define OSSL_DIGEST_PARAM_SSL3_MS    "ssl3-ms"   /* octet string */
#define OSSL_DIGEST_PARAM_PAD_TYPE   "pad_type"  /* uint */
#define OSSL_DIGEST_PARAM_MICALG     "micalg"    /* utf8 string */
#define OSSL_DIGEST_PARAM_BLOCK_SIZE "blocksize" /* size_t */
#define OSSL_DIGEST_PARAM_SIZE       "size"      /* size_t */
#define OSSL_DIGEST_PARAM_FLAGS      "flags"     /* ulong */

/* Known DIGEST names (not a complete list) */
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
#define OSSL_MAC_PARAM_CIPHER       "cipher"     /* utf8 string */
#define OSSL_MAC_PARAM_DIGEST       "digest"     /* utf8 string */
#define OSSL_MAC_PARAM_ENGINE       "engine"     /* utf8 string */
#define OSSL_MAC_PARAM_PROPERTIES   "properties" /* utf8 string */
#define OSSL_MAC_PARAM_SIZE         "size"       /* size_t */

/* Known MAC names (not a complete list) */
#define OSSL_MAC_NAME_CMAC          "CMAC"
#define OSSL_MAC_NAME_HMAC          "HMAC"
#define OSSL_MAC_NAME_KMAC128       "KMAC128"
#define OSSL_MAC_NAME_KMAC256       "KMAC256"

/* PKEY parameters */
/* Diffie-Hellman Parameters */
#define OSSL_PKEY_PARAM_DH_P         "dh-p"
#define OSSL_PKEY_PARAM_DH_G         "dh-g"
#define OSSL_PKEY_PARAM_DH_Q         "dh-q"
/* Diffie-Hellman Keys */
#define OSSL_PKEY_PARAM_DH_PUB_KEY   "dh-pub"
#define OSSL_PKEY_PARAM_DH_PRIV_KEY  "dh-priv"

/* Key Exchange parameters */

#define OSSL_EXCHANGE_PARAM_PAD      "exchange-pad" /* uint */

# ifdef __cplusplus
}
# endif

#endif
