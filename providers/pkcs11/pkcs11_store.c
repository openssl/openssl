#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include <openssl/store.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"

/* Private functions */

#define PKCS11_STORE_ALGO_DESCRIPTION     "PKSC11 store"

static char* pkcs11_store_description = PKCS11_STORE_ALGO_DESCRIPTION;

static OSSL_FUNC_store_open_fn                  pkcs11_store_open;
static OSSL_FUNC_store_attach_fn                pkcs11_store_attach;
static OSSL_FUNC_store_settable_ctx_params_fn   pkcs11_store_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn        pkcs11_store_set_ctx_params;
static OSSL_FUNC_store_load_fn                  pkcs11_store_load;
static OSSL_FUNC_store_eof_fn                   pkcs11_store_eof;
static OSSL_FUNC_store_close_fn                 pkcs11_store_close;

const OSSL_DISPATCH pkcs11_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN,     (void (*)(void))pkcs11_store_open },
    { OSSL_FUNC_STORE_ATTACH,   (void (*)(void))pkcs11_store_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
                                (void (*)(void))pkcs11_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,
                                (void (*)(void))pkcs11_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD,     (void (*)(void))pkcs11_store_load },
    { OSSL_FUNC_STORE_EOF,      (void (*)(void))pkcs11_store_eof },
    { OSSL_FUNC_STORE_CLOSE,    (void (*)(void))pkcs11_store_close },
    { 0, NULL },
};

static const OSSL_PARAM pkcs11_store_settable_ctx_params_tbl[] = {
    OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
    OSSL_PARAM_int(OSSL_STORE_PARAM_SERIAL, NULL),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_store_open(void *provctx, const char *uri)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_STORE_CTX* ctx = NULL;
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;

    return ctx;
}

void *pkcs11_store_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    return NULL;
}

static const OSSL_PARAM *pkcs11_store_settable_ctx_params(void *provctx)
{
    return pkcs11_store_settable_ctx_params_tbl;
}

static int pkcs11_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PKCS11_STORE_CTX *ctx = (PKCS11_STORE_CTX *)loaderctx;
    int ret = 0;

    if (ctx == NULL)
        goto end;
    /*
     *     OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
    OSSL_PARAM_int(OSSL_STORE_PARAM_SERIAL, NULL),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
*/
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->expected_type))
        goto end;
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
    if (p != NULL) {
        const unsigned char *der = NULL;
        size_t der_len = 0;
        X509_NAME *x509_name = NULL;
        unsigned long hash = 0;
        int ok;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &der_len)
            || (x509_name = d2i_X509_NAME(NULL, &der, der_len)) == NULL)
            goto end;
        hash = X509_NAME_hash_ex(x509_name,
                                 ossl_prov_ctx_get0_libctx(&ctx->pkcs11_ctx->ctx),
                                 NULL, &ok);
        snprintf(ctx->search_name, sizeof(ctx->search_name),
                     "%08lx", hash);
        X509_NAME_free(x509_name);
        if (ok == 0)
            goto end;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ISSUER);
    if (p != NULL) {
        const unsigned char *der = NULL;
        size_t der_len = 0;
        X509_NAME *x509_name = NULL;
        unsigned long hash = 0;
        int ok;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &der_len)
            || (x509_name = d2i_X509_NAME(NULL, &der, der_len)) == NULL)
            goto end;
        hash = X509_NAME_hash_ex(x509_name,
                    ossl_prov_ctx_get0_libctx(&ctx->pkcs11_ctx->ctx),
                                 NULL, &ok);
        snprintf(ctx->search_issuer, sizeof(ctx->search_issuer),
                     "%08lx", hash);
        X509_NAME_free(x509_name);
        if (ok == 0)
            goto end;
    }
    ret = 1;
end:

    return ret;
}

static int pkcs11_store_load(void *loaderctx,
                     OSSL_CALLBACK *object_cb, void *object_cbarg,
                     OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return 0;
}

static int pkcs11_store_eof(void *loaderctx)
{
    return 0;
}

static int pkcs11_store_close(void *loaderctx)
{
    PKCS11_STORE_CTX* ctx = (PKCS11_STORE_CTX *)loaderctx;
    if (ctx != NULL)
        OPENSSL_free(ctx);

    return 1;
}

OSSL_ALGORITHM *pkcs11_store_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
{
    OPENSSL_STACK *algo_sk = OPENSSL_sk_new_null();
    OSSL_ALGORITHM *tblalgo = NULL;
    OSSL_ALGORITHM *ptblalgo = NULL;
    OSSL_ALGORITHM* item = NULL;
    int i = 0;
    pkcs11_add_algorithm(algo_sk, "file", id,
                         pkcs11_store_functions,
                         pkcs11_store_description);
    i = OPENSSL_sk_num(algo_sk);
    if (i > 0) {
        tblalgo = OPENSSL_zalloc((i + 1) * sizeof(*tblalgo));
        ptblalgo = (OSSL_ALGORITHM *)tblalgo;
        item = (OSSL_ALGORITHM *)OPENSSL_sk_value(algo_sk, i - 1);
        memcpy(ptblalgo, item, sizeof(*item));
        OPENSSL_free(item);
        OPENSSL_sk_free(algo_sk);
    }
    return tblalgo;
}
