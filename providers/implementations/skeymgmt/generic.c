/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/skey.h"
#include "crypto/types.h"
#include "internal/param_build_set.h"

static OSSL_FUNC_skeymgmt_import_fn generic_import;
static OSSL_FUNC_skeymgmt_export_fn generic_export;
static OSSL_FUNC_skeymgmt_free_fn generic_free;

static void generic_free(void *keydata)
{
    SKEY *generic = keydata;

    if (generic == NULL)
        return;

    OPENSSL_free(generic->data);
    OPENSSL_free(generic);
}

static void *generic_import(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    const OSSL_PARAM *raw_bytes;
    SKEY *generic;
    int ok = 0;

    if (!ossl_prov_is_running())
        return NULL;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return NULL;

    raw_bytes = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (raw_bytes == NULL)
        return NULL;

    generic = OPENSSL_zalloc(sizeof(SKEY));
    generic->libctx = libctx;

    generic->type = SKEY_TYPE_GENERIC;

    if ((generic->data = OPENSSL_memdup(raw_bytes->data, raw_bytes->data_size)) == NULL) {
        ok = 0;
        goto end;
    }
    generic->length = raw_bytes->data_size;
    ok = 1;

end:
    if (ok == 0) {
        generic_free(generic);
        generic = NULL;
    }
    return generic;
}

static int generic_export(void *keydata, int selection,
                          OSSL_CALLBACK *param_callback, void *cbarg)
{
    SKEY *gen = keydata;
    OSSL_PARAM params[2];

    if (!ossl_prov_is_running() || gen == NULL)
        return 0;

    if (gen->type != SKEY_TYPE_GENERIC)
        return 0;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  gen->data, gen->length);
    params[1] = OSSL_PARAM_construct_end();

    return param_callback(params, cbarg);
}

const OSSL_DISPATCH ossl_generic_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))generic_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))generic_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))generic_export },
    OSSL_DISPATCH_END
};
