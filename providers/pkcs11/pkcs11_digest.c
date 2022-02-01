#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"

/* Private functions */

#define PKCS11_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1
#define PKCS11_DIGEST_ALGO_DESCRIPTION     "PKSC11 digest algo"

static char* pkcs11_digest_algo_description = PKCS11_DIGEST_ALGO_DESCRIPTION;

/* required functions */
static OSSL_FUNC_digest_newctx_fn               pkcs11_digest_newctx;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_init;
static OSSL_FUNC_digest_update_fn               pkcs11_digest_update;

static OSSL_FUNC_digest_final_fn                pkcs11_digest_final;
static OSSL_FUNC_digest_digest_fn               pkcs11_digest_digest;
static OSSL_FUNC_digest_freectx_fn              pkcs11_digest_freectx;
static OSSL_FUNC_digest_dupctx_fn               pkcs11_digest_dupctx;
static OSSL_FUNC_digest_get_params_fn           pkcs11_digest_get_params;
static OSSL_FUNC_digest_set_ctx_params_fn       pkcs11_digest_set_ctx_params;
static OSSL_FUNC_digest_get_ctx_params_fn       pkcs11_digest_get_ctx_params;
static OSSL_FUNC_digest_gettable_params_fn      pkcs11_digest_gettable_params;
static OSSL_FUNC_digest_settable_ctx_params_fn  pkcs11_digest_settable_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn  pkcs11_digest_gettable_ctx_params;

const OSSL_DISPATCH pkcs11_digest_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
};

static void *pkcs11_digest_newctx(void *provctx)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_DIGEST_CTX *ctx = NULL;
    char *propq_copy = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;

    return ctx;
}

static int pkcs11_digest_init(void *dctx, const OSSL_PARAM params[])
{
    PKCS11_DIGEST_CTX *ctx = (PKCS11_DIGEST_CTX *)dctx;
    
    if (ctx == NULL)
        return 0;

    ctx->type = CKF_DIGEST;
    ctx->digest = NID_undef;

    return 1;
}

static int pkcs11_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    return 1;
}

static int pkcs11_digest_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    return 1;
}

static int pkcs11_digest_digest(void *provctx, const unsigned char *in, size_t inl,
                     unsigned char *out, size_t *outl, size_t outsz)
{
    return 1;
}

static void pkcs11_digest_freectx(void *dctx)
{
    PKCS11_DIGEST_CTX *digestctx = (PKCS11_DIGEST_CTX *)dctx;
    PKCS11_CTX *ctx = NULL;
    
    if (digestctx == NULL) {
        ctx = digestctx->pkcs11_ctx;
        if (ctx != NULL) {
            fprintf(stdout, "@@@ provider: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
            fprintf(stdout, "@@@ - lib_functions ptr %p\n", ctx->lib_functions);
            if (digestctx->digest) {
                fprintf(stdout, "@@@ - Free Digest = %lu\n", digestctx->digest);
                fflush(stdout);
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, digestctx->digest);
            }
            digestctx->digest = 0;
        }
        OPENSSL_free(digestctx);
    }
}

static void *pkcs11_digest_dupctx(void *dctx)
{
    return NULL;
}

static int pkcs11_digest_get_params(OSSL_PARAM params[])
{
    return 1;
}

static int pkcs11_digest_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

static int pkcs11_digest_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM pkcs11_digest_gettable_params_tbl[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pkcs11_digest_gettable_params(void *provctx)
{
    return pkcs11_digest_gettable_params_tbl;
}

static const OSSL_PARAM *pkcs11_digest_settable_ctx_params(void *dctx, void *provctx)
{
    return NULL;
}

static const OSSL_PARAM *pkcs11_digest_gettable_ctx_params(void *dctx, void *provctx)
{
    return NULL;
}


OSSL_ALGORITHM *pkcs11_digest_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
{
    OPENSSL_STACK *algo_sk = OPENSSL_sk_new_null();
    OSSL_ALGORITHM *tblalgo = NULL;
    OSSL_ALGORITHM *ptblalgo = NULL;
    OSSL_ALGORITHM* item = NULL;
    int i = 0;
    for (i = 0; i < OPENSSL_sk_num(sk); i++)
    {
        PKCS11_TYPE_DATA_ITEM *item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(sk, i);
        if (item != NULL) {
            if (item->info.flags | CKF_DIGEST) {
                const char *name = pkcs11_mechanism2name_digest(item->type);
                if (name != NULL)
                    pkcs11_add_algorithm(algo_sk, name, id, pkcs11_digest_dp_tbl, pkcs11_digest_algo_description);
            }
        }
    }
    i = OPENSSL_sk_num(algo_sk);
    if (i > 0) {
        tblalgo = OPENSSL_zalloc((i + 1) * sizeof(*tblalgo));
        ptblalgo = (OSSL_ALGORITHM *)tblalgo;
        for(; i > 0; i--, ptblalgo++) {
            item = (OSSL_ALGORITHM *)OPENSSL_sk_value(algo_sk, i - 1);
            memcpy(ptblalgo, item, sizeof(*item));
            OPENSSL_free(item);
        }
        OPENSSL_sk_free(algo_sk);
    }
    return tblalgo;
}
