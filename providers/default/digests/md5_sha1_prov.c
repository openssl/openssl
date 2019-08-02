/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "internal/core_mkdigest.h"
#include "internal/md5_sha1.h"
#include "internal/provider_algs.h"

static OSSL_OP_digest_set_params_fn md5_sha1_set_params;

/* Special set_params method for SSL3 */
static int md5_sha1_set_params(void *vctx, OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    MD5_SHA1_CTX *ctx = (MD5_SHA1_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SSL3_MS);
        if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING)
            return md5_sha1_ctrl(ctx, EVP_CTRL_SSL3_MASTER_SECRET, p->data_size,
                                 p->data);
    }
    return 0;
}

OSSL_FUNC_DIGEST_CONSTRUCT_PARAMS(md5_sha1, MD5_SHA1_CTX,
                                  MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH,
                                  md5_sha1_init, md5_sha1_update, md5_sha1_final,
                                  md5_sha1_set_params)
