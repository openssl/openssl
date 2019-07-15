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


/* cipher parameters */
#define OSSL_CIPHER_PARAM_PADDING   "padding"    /* int */
#define OSSL_CIPHER_PARAM_MODE      "mode"       /* int */
#define OSSL_CIPHER_PARAM_BLOCK_SIZE "blocksize" /* int */
#define OSSL_CIPHER_PARAM_FLAGS     "flags"      /* ulong */
#define OSSL_CIPHER_PARAM_KEYLEN    "keylen"     /* int */
#define OSSL_CIPHER_PARAM_IVLEN     "ivlen"      /* int */
#define OSSL_CIPHER_PARAM_IV        "iv"         /* octet_string OR octet_ptr */
#define OSSL_CIPHER_PARAM_NUM       "num"        /* int */
#define OSSL_CIPHER_PARAM_AEAD_TAG           "tag"        /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD      "tlsaad"     /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD  "tlsaadpad"  /* size_t */
#define OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED "tlsivfixed" /* octet_string */
#define OSSL_CIPHER_PARAM_AEAD_IVLEN         "aeadivlen"  /* size_t */

/* digest parameters */
#define OSSL_DIGEST_PARAM_XOFLEN    "xoflen"
#define OSSL_DIGEST_PARAM_SSL3_MS   "ssl3-ms"
#define OSSL_DIGEST_PARAM_PAD_TYPE  "pad_type"
#define OSSL_DIGEST_PARAM_MICALG    "micalg"

# ifdef __cplusplus
}
# endif

#endif
