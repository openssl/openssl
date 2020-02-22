/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * MD5 and SHA-1 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "prov/md5_sha1.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

static OSSL_OP_digest_set_ctx_params_fn md5_sha1_set_ctx_params;
static OSSL_OP_digest_settable_ctx_params_fn md5_sha1_settable_ctx_params;

static const OSSL_PARAM known_md5_sha1_settable_ctx_params[] = {
    {OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    OSSL_PARAM_END
};

static const OSSL_PARAM *md5_sha1_settable_ctx_params(void)
{
    return known_md5_sha1_settable_ctx_params;
}

/* Special set_params method for SSL3 */
static int md5_sha1_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    MD5_SHA1_CTX *ctx = (MD5_SHA1_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS);
        if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING)
            return md5_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, p->data_size,
                                 p->data);
    }
    return 0;
}

/* md5_sha1_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    md5_sha1, MD5_SHA1_CTX, MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH, 0,
    md5_sha1_init, md5_sha1_update, md5_sha1_final,
    md5_sha1_settable_ctx_params, md5_sha1_set_ctx_params)
