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

PKCS11_TYPE_DATA_ITEM *pkcs11_digest_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type);

static char* pkcs11_digest_algo_description = PKCS11_DIGEST_ALGO_DESCRIPTION;

/* required functions */
static OSSL_FUNC_digest_newctx_fn               pkcs11_digest_newctx;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_md5_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha1_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha224_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha256_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha384_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha512_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha512_224_init;
static OSSL_FUNC_digest_init_fn                 pkcs11_digest_sha512_256_init;
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

#define PKCS11_PROV_FUNC_DIGEST_GET_PARAM(name, ckmid, nid, blksize, dgstsize)             \
static OSSL_FUNC_digest_get_params_fn pkcs11_digest_##name##_get_params;                       \
static int pkcs11_digest_##name##_get_params(OSSL_PARAM params[])              \
{                                                                              \
    return pkcs11_digest_default_get_params(params, blksize, dgstsize);   \
} \
static int pkcs11_digest_##name##_init(void *dctx, const OSSL_PARAM params[])   \
{                                                                                                   \
    return pkcs11_digest_default_init(dctx, params, ckmid, nid);    \
}

PKCS11_PROV_FUNC_DIGEST_GET_PARAM(md5, CKM_MD5, NID_md5, 64, 16)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha1, CKM_SHA_1, NID_sha1, 64, 20)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha224, CKM_SHA224, NID_sha224, 64, 28)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha256, CKM_SHA256, NID_sha256, 64, 32)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha384, CKM_SHA384, NID_sha384, 128, 48)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha512, CKM_SHA512, NID_sha512, 128, 64)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha512_224, CKM_SHA512_224, NID_sha512_224, 128, 28)
PKCS11_PROV_FUNC_DIGEST_GET_PARAM(sha512_256, CKM_SHA512_256, NID_sha512_256, 128, 32)
#define pkcs11_digest_get_param_fct(name) pkcs11_digest_##name##_get_params
#define pkcs11_digest_init_fct(name) pkcs11_digest_##name##_init

/* static int pkcs11_digest_md5_init(void *dctx, const OSSL_PARAM params[])
    return pkcs11_digest_init(dctx, CKM_MD5, NID_md5, 64, 16);
    return pkcs11_digest_init(dctx, CKM_SHA_1, NID_sha1, 64, 20);
    return pkcs11_digest_init(dctx, CKM_SHA224, NID_sha224, 64, 28);
    return pkcs11_digest_init(dctx, CKM_SHA256, NID_sha256, 64, 32);
    return pkcs11_digest_init(dctx, CKM_SHA384, NID_sha384, 128, 48);
    return pkcs11_digest_init(dctx, CKM_SHA512, NID_sha512, 128, 64);
    return pkcs11_digest_init(dctx, CKM_SHA512_224, NID_sha512_224, 128, 28);
    return pkcs11_digest_init(dctx, CKM_SHA512_256, NID_sha512_256, 128, 32);
}
*/


const OSSL_DISPATCH pkcs11_digest_md5_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_md5_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(md5) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha1_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha1_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha1) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha224_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha224_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha224) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha256_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha256_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha256) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha384_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha384_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha384) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha512_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha512_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha512) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha512_224_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha512_224_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha512_224) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const OSSL_DISPATCH pkcs11_digest_sha512_256_dp_tbl[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,               (void (*)(void))pkcs11_digest_newctx },
    { OSSL_FUNC_DIGEST_INIT,                 (void (*)(void))pkcs11_digest_sha512_256_init },
    { OSSL_FUNC_DIGEST_UPDATE,               (void (*)(void))pkcs11_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,                (void (*)(void))pkcs11_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,               (void (*)(void))pkcs11_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX,              (void (*)(void))pkcs11_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,               (void (*)(void))pkcs11_digest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS,           (void (*)(void))pkcs11_digest_get_param_fct(sha512_256) },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       (void (*)(void))pkcs11_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      (void (*)(void))pkcs11_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  (void (*)(void))pkcs11_digest_gettable_ctx_params },
    {0, NULL}
};

const PKCS11_DIGEST_MAP pkcs11_digest_map[] = {
    {CKM_MD5,        SN_md5,        NID_md5,        pkcs11_digest_md5_dp_tbl},
    {CKM_SHA_1,      SN_sha1,       NID_sha1,       pkcs11_digest_sha1_dp_tbl},
    {CKM_SHA224,     SN_sha224,     NID_sha224,     pkcs11_digest_sha224_dp_tbl},
    {CKM_SHA256,     SN_sha256,     NID_sha256,     pkcs11_digest_sha256_dp_tbl},
    {CKM_SHA384,     SN_sha384,     NID_sha384,     pkcs11_digest_sha384_dp_tbl},
    {CKM_SHA512,     SN_sha512,     NID_sha512,     pkcs11_digest_sha512_dp_tbl},
    {CKM_SHA512_224, SN_sha512_224, NID_sha512_224, pkcs11_digest_sha512_224_dp_tbl},
    {CKM_SHA512_256, SN_sha512_256, NID_sha512_256, pkcs11_digest_sha512_256_dp_tbl},
    {0, NULL, 0, NULL}
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

static int pkcs11_digest_default_init(void *dctx, const OSSL_PARAM params[], unsigned long type, int nid)
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
    rv = ctx->pkcs11_ctx->lib_functions->C_DigestInit(ctx->pkcs11_ctx->session, &mech);
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
    int ret = 0;
    if (ctx == NULL)
        return 0;

    rv = ctx->pkcs11_ctx->lib_functions->C_DigestUpdate(ctx->pkcs11_ctx->session,
                                                        (CK_BYTE *)in, inl);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static int pkcs11_digest_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    PKCS11_DIGEST_CTX *ctx = (PKCS11_DIGEST_CTX *)dctx;
    CK_RV rv = CKR_OK;
    CK_ULONG ul = outsz;
    int ret = 0;
    if (ctx == NULL)
        goto end;
    if (outl == NULL)
        goto end;

    rv = ctx->pkcs11_ctx->lib_functions->C_DigestFinal(ctx->pkcs11_ctx->session,
                                                        (CK_BYTE *)out, &ul);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *outl = ul;
    ret = 1;
end:
    return ret;
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
            if (digestctx->hdigest) {
                fprintf(stdout, "@@@ - Free Digest = %lu\n", digestctx->hdigest);
                fflush(stdout);
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, digestctx->hdigest);
            }
            digestctx->hdigest = 0;
        }
        OPENSSL_free(digestctx);
    }
}

static void *pkcs11_digest_dupctx(void *dctx)
{
    return NULL;
}

int pkcs11_digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz)
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
    return pkcs11_digest_gettable_params_tbl;
}

static const OSSL_PARAM *pkcs11_digest_gettable_ctx_params(void *dctx, void *provctx)
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
                        pkcs11_add_algorithm(algo_sk, pdm->SN, id, pdm->table, pkcs11_digest_algo_description);
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

PKCS11_TYPE_DATA_ITEM *pkcs11_digest_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type)
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
