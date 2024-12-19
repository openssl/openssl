/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define NAME_1          X25519
#define NAME_2          X448

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include "crypto/ecx.h"
#include "prov/securitycheck.h"

#include "hybrid_kmgmt.inc"

const HYBRID_ALG_INFO COMMON_NAME(info) = {
    NUM_ALGS,
    {
        {
            "X25519",
            X25519_KEYLEN,              /* public key length (bytes) */
            X25519_BITS,                /* bits */
            X25519_SECURITY_BITS,       /* security bits */
            SHA256_DIGEST_LENGTH,       /* shared secret (bytes) */
            X25519_KEYLEN               /* ciphertext bytes */
        },
        {
            "X448",
            X448_KEYLEN,                /* public key length (bytes) */
            X448_BITS,                  /* bits */
            X448_SECURITY_BITS,         /* security bits */
            SHA512_DIGEST_LENGTH,       /* shared secret (bytes) */
            X448_KEYLEN                 /* ciphertext bytes */
        }
    }
};

#define ECX_KEY_TYPES()                                                        \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                 \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

const OSSL_PARAM OSSL_NAME(gettable_params)[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    ECX_KEY_TYPES(),
    OSSL_FIPS_IND_GETTABLE_CTX_PARAM()
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(settable_params)[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(import_types)[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(export_types)[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(ctx_gettable_params)[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(ctx_settable_params)[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, NULL, 0),
        OSSL_PARAM_END
};
