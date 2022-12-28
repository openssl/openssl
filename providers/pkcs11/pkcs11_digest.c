#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include <internal/provider.h>
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"

/* Private functions */

#define PKCS11_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1
#define PKCS11_DIGEST_ALGO_DESCRIPTION     "PKSC11 digest algo"

PKCS11_TYPE_DATA_ITEM *pkcs11_digest_get_mech_data(PKCS11_CTX *provctx,
                                                   CK_MECHANISM_TYPE type);

static char* pkcs11_digest_algo_description = PKCS11_DIGEST_ALGO_DESCRIPTION;

/* required functions */
static OSSL_FUNC_digest_newctx_fn               pkcs11_digest_newctx;
/* pkcs11_digest_init is defined for each digest further down */
static OSSL_FUNC_digest_update_fn               pkcs11_digest_update;
static OSSL_FUNC_digest_final_fn                pkcs11_digest_final;
static OSSL_FUNC_digest_freectx_fn              pkcs11_digest_freectx;
/* pkcs11_digest_get_param is defined for each digest further down */
static OSSL_FUNC_digest_gettable_params_fn      pkcs11_digest_gettable_params;

struct pkcs11_digest_map_st{
    int mechanics;
    const char* SN;
    int nid;
    const OSSL_DISPATCH *table;
};

typedef struct pkcs11_digest_map_st PKCS11_DIGEST_MAP;
static int pkcs11_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                            size_t paramsz);
static int pkcs11_digest_default_init(void *dctx, const OSSL_PARAM params[],
                                      unsigned long type, int nid);

#define PKCS11_DIGEST_INIT_FCT(name)        pkcs11_digest_##name##_init
#define PKCS11_DIGEST_GET_PARAM_FCT(name)   pkcs11_digest_##name##_get_params
#define PKCS11_DIGEST_DB_TBL(name)          pkcs11_digest_##name##_dp_tbl

#define PKCS11_PROV_FUNC_DIGEST(name, ckmid, nid, blksize, dgstsize)                    \
/* define the init function for the specific digest */                                  \
static int PKCS11_DIGEST_INIT_FCT(name)(void *dctx, const OSSL_PARAM params[])          \
{                                                                                       \
    return pkcs11_digest_default_init(dctx, params, ckmid, nid);                        \
}                                                                                       \
static OSSL_FUNC_digest_init_fn                 PKCS11_DIGEST_INIT_FCT(name);           \
/* define the get param function for the specific digest */                             \
static OSSL_FUNC_digest_get_params_fn PKCS11_DIGEST_GET_PARAM_FCT(name);                \
static int PKCS11_DIGEST_GET_PARAM_FCT(name)(OSSL_PARAM params[])                       \
{                                                                                       \
    return pkcs11_digest_default_get_params(params, blksize, dgstsize);                 \
}                                                                                       \
/* define the dispatch table for the specific digest */                                 \
const OSSL_DISPATCH PKCS11_DIGEST_DB_TBL(name)[] = {                                                \
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },                \
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))PKCS11_DIGEST_INIT_FCT(name) },        \
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },                \
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },                 \
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },               \
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))PKCS11_DIGEST_GET_PARAM_FCT(name) },   \
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },       \
    {0, NULL}                                                                                       \
};

PKCS11_PROV_FUNC_DIGEST(md5, CKM_MD5, NID_md5, 64, 16)
PKCS11_PROV_FUNC_DIGEST(sha1, CKM_SHA_1, NID_sha1, 64, 20)
PKCS11_PROV_FUNC_DIGEST(sha224, CKM_SHA224, NID_sha224, 64, 28)
PKCS11_PROV_FUNC_DIGEST(sha256, CKM_SHA256, NID_sha256, 64, 32)
PKCS11_PROV_FUNC_DIGEST(sha384, CKM_SHA384, NID_sha384, 128, 48)
PKCS11_PROV_FUNC_DIGEST(sha512, CKM_SHA512, NID_sha512, 128, 64)
PKCS11_PROV_FUNC_DIGEST(sha512_224, CKM_SHA512_224, NID_sha512_224, 128, 28)
PKCS11_PROV_FUNC_DIGEST(sha512_256, CKM_SHA512_256, NID_sha512_256, 128, 32)

const PKCS11_DIGEST_MAP pkcs11_digest_map[] = {
    {CKM_MD5,        SN_md5,        NID_md5,        PKCS11_DIGEST_DB_TBL(md5)},
    {CKM_SHA_1,      SN_sha1,       NID_sha1,       PKCS11_DIGEST_DB_TBL(sha1)},
    {CKM_SHA224,     SN_sha224,     NID_sha224,     PKCS11_DIGEST_DB_TBL(sha224)},
    {CKM_SHA256,     SN_sha256,     NID_sha256,     PKCS11_DIGEST_DB_TBL(sha256)},
    {CKM_SHA384,     SN_sha384,     NID_sha384,     PKCS11_DIGEST_DB_TBL(sha384)},
    {CKM_SHA512,     SN_sha512,     NID_sha512,     PKCS11_DIGEST_DB_TBL(sha512)},
    {CKM_SHA512_224, SN_sha512_224, NID_sha512_224, PKCS11_DIGEST_DB_TBL(sha512_224)},
    {CKM_SHA512_256, SN_sha512_256, NID_sha512_256, PKCS11_DIGEST_DB_TBL(sha512_256)},
    {0, NULL, 0, NULL}
};

static const OSSL_PARAM pkcs11_digest_gettable_params_tbl[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

static void *pkcs11_digest_newctx(void *provctx)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_DIGEST_CTX *ctx = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;

    return ctx;
}

static int pkcs11_digest_default_init(void *dctx, const OSSL_PARAM params[],
                                      unsigned long type, int nid)
{
    PKCS11_DIGEST_CTX *ctx = (PKCS11_DIGEST_CTX *)dctx;
    PKCS11_CTX *provctx = NULL;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_RV rv = CKR_OK;
    int ret = 0;

    if (ctx == NULL)
        return 0;
    provctx = ctx->pkcs11_ctx;
    if (provctx == NULL)
        return 0;

    ctx->type = type;
    ctx->nid = nid;
    ctx->hdigest = 0;
    ctx->mechdata = pkcs11_digest_get_mech_data((PKCS11_CTX *)provctx, type);
    mech.mechanism = ctx->mechdata->type;
    rv = ctx->pkcs11_ctx->lib_functions->C_DigestInit(ctx->pkcs11_ctx->session,
                                                      &mech);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static int pkcs11_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    PKCS11_DIGEST_CTX *ctx = (PKCS11_DIGEST_CTX *)dctx;
    CK_RV rv = CKR_OK;
    CK_ULONG ckinl = inl;
    int ret = 0;
    if (ctx == NULL)
        return 0;

    rv = ctx->pkcs11_ctx->lib_functions->C_DigestUpdate(ctx->pkcs11_ctx->session,
                                                        (CK_BYTE *)in, ckinl);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static int pkcs11_digest_final(void *dctx, unsigned char *out, size_t *outl,
                               size_t outsz)
{
    PKCS11_DIGEST_CTX *ctx = (PKCS11_DIGEST_CTX *)dctx;
    CK_RV rv = CKR_OK;
    CK_ULONG ckoutl = outsz;
    int ret = 0;
    if (ctx == NULL)
        goto end;
    if (outl == NULL)
        goto end;

    rv = ctx->pkcs11_ctx->lib_functions->C_DigestFinal(ctx->pkcs11_ctx->session,
                                                       (CK_BYTE *)out, &ckoutl);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *outl = ckoutl;
    ret = 1;
end:
    return ret;
}

static void pkcs11_digest_freectx(void *dctx)
{
    PKCS11_DIGEST_CTX *digestctx = (PKCS11_DIGEST_CTX *)dctx;
    PKCS11_CTX *ctx = NULL;
    
    if (digestctx == NULL) {
        ctx = digestctx->pkcs11_ctx;
        if (ctx != NULL) {
            fprintf(stdout, "@@@ provider: %s\n", ossl_provider_name((OSSL_PROVIDER *)ctx->ctx.handle));
            fprintf(stdout, "@@@ - lib_functions ptr %p\n", ctx->lib_functions);
            if (digestctx->hdigest) {
                fprintf(stdout, "@@@ - Free Digest = %lu\n", digestctx->hdigest);
                fflush(stdout);
                (void)ctx->lib_functions->C_DestroyObject(ctx->session,
                                                          digestctx->hdigest);
            }
            digestctx->hdigest = 0;
        }
        OPENSSL_free(digestctx);
    }
}

int pkcs11_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                     size_t paramsz)
{
    OSSL_PARAM *p = NULL;
    int ret = 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz))
        goto end;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz))
        goto end;
    ret = 1;
end:
    return ret;
}

static const OSSL_PARAM *pkcs11_digest_gettable_params(void *provctx)
{
    return pkcs11_digest_gettable_params_tbl;
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
                const PKCS11_DIGEST_MAP* pdm = pkcs11_digest_map;
                for(;pdm->mechanics != 0;pdm++){
                    if (item->type == pdm->mechanics) {
                        pkcs11_add_algorithm(algo_sk, pdm->SN, id, pdm->table,
                                             pkcs11_digest_algo_description);
                     }
                }
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

PKCS11_TYPE_DATA_ITEM *pkcs11_digest_get_mech_data(PKCS11_CTX *provctx,
                                                   CK_MECHANISM_TYPE type)
{
    int i = 0;
    int ii = 0;
    PKCS11_SLOT *slot = NULL;
    PKCS11_TYPE_DATA_ITEM *pdigest = NULL;

    for (ii = 0; ii < OPENSSL_sk_num(provctx->slots); ii++) {
        slot = (PKCS11_SLOT *)OPENSSL_sk_value(provctx->slots, ii);
        if (slot->slotid == provctx->sel_slot) {
            for (i = 0; i < OPENSSL_sk_num(slot->digest.items); i++) {
                pdigest = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->digest.items, i);
                if (pdigest->type == type)
                    return pdigest;
            }
        }
    }
    return NULL;
}
