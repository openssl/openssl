/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "crypto/sha.h"

static OSSL_OP_digest_set_ctx_params_fn sha1_set_ctx_params;
static OSSL_OP_digest_settable_ctx_params_fn sha1_settable_ctx_params;

static const OSSL_PARAM known_sha1_settable_ctx_params[] = {
    {OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    OSSL_PARAM_END
};
static const OSSL_PARAM *sha1_settable_ctx_params(void)
{
    return known_sha1_settable_ctx_params;
}

/* Special set_params method for SSL3 */
static int sha1_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    SHA_CTX *ctx = (SHA_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS);
        if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING)
            return sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, p->data_size,
                             p->data);
    }
    return 0;
}

/* sha1_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    sha1, SHA_CTX, SHA_CBLOCK, SHA_DIGEST_LENGTH, EVP_MD_FLAG_DIGALGID_ABSENT,
    SHA1_Init, SHA1_Update, SHA1_Final,
    sha1_settable_ctx_params, sha1_set_ctx_params)

/* sha224_functions */
IMPLEMENT_digest_functions(sha224, SHA256_CTX,
                           SHA256_CBLOCK, SHA224_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           SHA224_Init, SHA224_Update, SHA224_Final)

/* sha256_functions */
IMPLEMENT_digest_functions(sha256, SHA256_CTX,
                           SHA256_CBLOCK, SHA256_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           SHA256_Init, SHA256_Update, SHA256_Final)

/* sha384_functions */
IMPLEMENT_digest_functions(sha384, SHA512_CTX,
                           SHA512_CBLOCK, SHA384_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           SHA384_Init, SHA384_Update, SHA384_Final)

/* sha512_functions */
IMPLEMENT_digest_functions(sha512, SHA512_CTX,
                           SHA512_CBLOCK, SHA512_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           SHA512_Init, SHA512_Update, SHA512_Final)

/* sha512_224_functions */
IMPLEMENT_digest_functions(sha512_224, SHA512_CTX,
                           SHA512_CBLOCK, SHA224_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           sha512_224_init, SHA512_Update, SHA512_Final)

/* sha512_256_functions */
IMPLEMENT_digest_functions(sha512_256, SHA512_CTX,
                           SHA512_CBLOCK, SHA256_DIGEST_LENGTH,
                           EVP_MD_FLAG_DIGALGID_ABSENT,
                           sha512_256_init, SHA512_Update, SHA512_Final)

