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
    int ok = 1;

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

    if (!OSSL_PARAM_get_octet_string(raw_bytes, (void **)&generic->data, 0,
                                     &generic->length)) {
        ok = 0;
        goto end;
    }

end:
    if (!ok) {
        generic_free(generic);
        generic = NULL;
    }
    return generic;
}

static int generic_export(void *keydata, int selection,
                          OSSL_CALLBACK *param_callback, void *cbarg)
{
    SKEY *generic = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!ossl_prov_is_running() || generic == NULL)
        return 0;

    if (generic->type != SKEY_TYPE_GENERIC)
        return 0;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_SKEY_PARAM_RAW_BYTES,
                                          generic->data, generic->length)) {
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

const OSSL_DISPATCH ossl_generic_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))generic_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))generic_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))generic_export },
    OSSL_DISPATCH_END
};
