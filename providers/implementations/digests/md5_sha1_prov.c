/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <opentls/crypto.h>
#include <opentls/evp.h>
#include <opentls/params.h>
#include <opentls/core_names.h>
#include "prov/md5_sha1.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

static Otls_OP_digest_set_ctx_params_fn md5_sha1_set_ctx_params;
static Otls_OP_digest_settable_ctx_params_fn md5_sha1_settable_ctx_params;

static const Otls_PARAM known_md5_sha1_settable_ctx_params[] = {
    {Otls_DIGEST_PARAM_tls3_MS, Otls_PARAM_OCTET_STRING, NULL, 0, 0},
    Otls_PARAM_END
};

static const Otls_PARAM *md5_sha1_settable_ctx_params(void)
{
    return known_md5_sha1_settable_ctx_params;
}

/* Special set_params method for tls3 */
static int md5_sha1_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    const Otls_PARAM *p;
    MD5_SHA1_CTX *ctx = (MD5_SHA1_CTX *)vctx;

    if (ctx != NULL && params != NULL) {
        p = Otls_PARAM_locate_const(params, Otls_DIGEST_PARAM_tls3_MS);
        if (p != NULL && p->data_type == Otls_PARAM_OCTET_STRING)
            return md5_sha1_ctrl(ctx, EVP_CTRL_tls3_MASTER_SECRET, p->data_size,
                                 p->data);
    }
    return 0;
}

/* md5_sha1_functions */
IMPLEMENT_digest_functions_with_settable_ctx(
    md5_sha1, MD5_SHA1_CTX, MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH, 0,
    md5_sha1_init, md5_sha1_update, md5_sha1_final,
    md5_sha1_settable_ctx_params, md5_sha1_set_ctx_params)
