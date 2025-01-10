/*
 * C TODO
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

static OSSL_FUNC_skeymgmt_import_fn aes_import;
static OSSL_FUNC_skeymgmt_export_fn aes_export;
static OSSL_FUNC_skeymgmt_free_fn aes_free;

static void aes_free(void *keydata)
{
    SKEY *aes = keydata;

    if (aes == NULL)
        return;

    OPENSSL_free(aes->data);
    OPENSSL_free(aes);
}

static void *aes_import(void *provctx, int selection,
                        const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    const OSSL_PARAM *raw_bytes;
    SKEY *aes;
    int ok = 1;

    if (!ossl_prov_is_running())
        return NULL;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return NULL;

    raw_bytes = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (raw_bytes == NULL)
        return NULL;

    aes = OPENSSL_zalloc(sizeof(SKEY));
    aes->libctx = libctx;

    aes->type = SKEY_TYPE_AES;

    if (!OSSL_PARAM_get_octet_string(raw_bytes, (void **)&aes->data, 0,
                                     &aes->length)) {
        ok = 0;
        goto end;
    }

    if (aes->length != 16 && aes->length != 24 && aes->length != 32) {
        ok = 0;
        goto end;
    }

end:
    if (!ok) {
        aes_free(aes);
        aes = NULL;
    }
    return aes;
}

static int aes_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    SKEY *aes = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!ossl_prov_is_running() || aes == NULL)
        return 0;

    if (aes->type != SKEY_TYPE_AES)
        return 0;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_SKEY_PARAM_RAW_BYTES,
                                          aes->data, aes->length)) {
        ok = 0;
        goto err;
    }

    if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        ok = 0;
        goto err;
    }

    ok = param_callback(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

const OSSL_DISPATCH ossl_aes_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))aes_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))aes_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))aes_export },
    OSSL_DISPATCH_END
};
