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

#define RSA_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1
#define PKCS11_SIGNATURE_ALGO_DESCRIPTION     "PKSC11 signature algo"

static char* pkcs11_signature_algo_description = PKCS11_SIGNATURE_ALGO_DESCRIPTION;

/* required functions */
static OSSL_FUNC_signature_newctx_fn                    pkcs11_signature_newctx;
static OSSL_FUNC_signature_sign_init_fn                 pkcs11_signature_rsa_sign_init;
static OSSL_FUNC_signature_sign_fn                      pkcs11_signature_sign;
static OSSL_FUNC_signature_verify_init_fn               pkcs11_signature_verify_init;
static OSSL_FUNC_signature_verify_fn                    pkcs11_signature_verify;
static OSSL_FUNC_signature_freectx_fn                   pkcs11_signature_freectx;
static OSSL_FUNC_signature_dupctx_fn                    pkcs11_signature_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn            pkcs11_signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn       pkcs11_signature_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn            pkcs11_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn       pkcs11_signature_settable_ctx_params;

const OSSL_DISPATCH pkcs11_rsa_sign_dp_tbl[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,                   (void (*)(void))pkcs11_signature_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,                (void (*)(void))pkcs11_signature_rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                     (void (*)(void))pkcs11_signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,              (void (*)(void))pkcs11_signature_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,                   (void (*)(void))pkcs11_signature_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX,                  (void (*)(void))pkcs11_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,                   (void (*)(void))pkcs11_signature_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,           (void (*)(void))pkcs11_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,      (void (*)(void))pkcs11_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,           (void (*)(void))pkcs11_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,      (void (*)(void))pkcs11_signature_settable_ctx_params },
};

static const OSSL_PARAM pkcs11_sign_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pkcs11_sign_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_END
};


static void *pkcs11_signature_newctx(void *provctx, const char *propq)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_SIGN_CTX *ctx = NULL;
    char *propq_copy = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL
        || (propq != NULL
            && (propq_copy = OPENSSL_strdup(propq)) == NULL)) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;

    return ctx;
}

static int pkcs11_signature_rsa_sign_init(void *sigctx, void *vrsa, const OSSL_PARAM params[])
{
    PKCS11_KEY *pkey = (PKCS11_KEY *)vrsa;
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;

    ctx->pkey = pkey;
    ctx->type = CKM_RSA_PKCS;
    ctx->digest_nid = NID_undef;
    ctx->isinit = 0;

    return 1;
}

CK_ULONG pkcs11_nid2mechanism_digest(int nid, CK_ULONG type)
{
    switch (nid) {
        case NID_md5:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_MD5_RSA_PKCS;
            }
        case NID_sha1:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_SHA1_RSA_PKCS;
                case CKM_RSA_PKCS_PSS:
                    return CKM_SHA1_RSA_PKCS_PSS;
            }
        case NID_sha224:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_SHA224_RSA_PKCS;
                case CKM_RSA_PKCS_PSS:
                    return CKM_SHA224_RSA_PKCS_PSS;
            }
        case NID_sha256:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_SHA256_RSA_PKCS;
                case CKM_RSA_PKCS_PSS:
                    return CKM_SHA1_RSA_PKCS_PSS;
            }
        case NID_sha384:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_SHA384_RSA_PKCS;
                case CKM_RSA_PKCS_PSS:
                    return CKM_SHA384_RSA_PKCS_PSS;
            }
        case NID_sha512:
            switch(type) {
                case CKM_RSA_PKCS:
                    return CKM_SHA512_RSA_PKCS;
                case CKM_RSA_PKCS_PSS:
                    return CKM_SHA512_RSA_PKCS_PSS;
            }
    }
    return CKM_NULL;
}

static int pkcs11_signature_sign(void *sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    /* todo call pkcs hw to do signing */
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_RV rv = CKR_OK;
    CK_ULONG cksiglen = sigsize;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    CK_BYTE_PTR ptbs = (CK_BYTE_PTR)tbs;
    int ret = 0;

    if (!ctx)
        goto end;

    mech.mechanism = pkcs11_nid2mechanism_digest(ctx->digest_nid, ctx->type);
    if (mech.mechanism == CKM_NULL)
        goto end;

    if (!ctx->isinit) {
        /* Initialize with padding mode */
        rv = ctx->pkcs11_ctx->lib_functions->C_SignInit(ctx->pkcs11_ctx->session,
                                                        &mech, ctx->pkey->priv);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 1;
    }
    rv = ctx->pkcs11_ctx->lib_functions->C_Sign(ctx->pkcs11_ctx->session,
                                                ptbs, tbslen, psig, &cksiglen);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *siglen = cksiglen;
    ret = 1;
end:
    return ret;
}

static int pkcs11_signature_verify_init(void *sigctx, void *vrsa,
                           const OSSL_PARAM params[])
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = (PKCS11_KEY *)vrsa;
    int ret = 0;

    ctx->pkey = pkey;
    switch(pkey->keymgmt_ctx->type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        ctx->type = CKM_RSA_PKCS;
        break;
    default:
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static int pkcs11_signature_verify(void *sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    CK_BYTE_PTR ptbs = (CK_BYTE_PTR)tbs;
    int ret = 0;

    if (!ctx)
        goto end;

    mech.mechanism = pkcs11_nid2mechanism_digest(ctx->digest_nid, ctx->type);
    if (mech.mechanism == CKM_NULL)
        goto end;

    if (!ctx->isinit) {
        /* Initialize with padding mode */
        rv = ctx->pkcs11_ctx->lib_functions->C_VerifyInit(ctx->pkcs11_ctx->session,
                                                          &mech, ctx->pkey->pub);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 1;
    }
    rv = ctx->pkcs11_ctx->lib_functions->C_Verify(ctx->pkcs11_ctx->session,
                                                  ptbs, tbslen, psig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

static void pkcs11_signature_freectx(void *sigctx)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    if (ctx != NULL)
        OPENSSL_free(ctx);
}

static void *pkcs11_signature_dupctx(void *sigctx)
{
    PKCS11_SIGN_CTX *source_ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_SIGN_CTX *dest_ctx = NULL;

    if (source_ctx == NULL)
        goto end;
    if ((dest_ctx = OPENSSL_zalloc(sizeof(*dest_ctx))) == NULL) {
        OPENSSL_free(dest_ctx);
        return NULL;
    }
    dest_ctx->pkey = source_ctx->pkey;
    dest_ctx->type = source_ctx->type;
    dest_ctx->digest_nid = source_ctx->digest_nid;
    dest_ctx->pkcs11_ctx = source_ctx->pkcs11_ctx;

end:
    return dest_ctx;
}

static int pkcs11_signature_get_ctx_params(void *sigctx, OSSL_PARAM *params)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    OSSL_PARAM *p;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            switch (ctx->type) {
            case CKM_RSA_PKCS:
                if (!OSSL_PARAM_set_int(p, RSA_PKCS1_PADDING))
                    goto end;
                break;
            case  CKM_RSA_PKCS_PSS:
                if (!OSSL_PARAM_set_int(p, RSA_PKCS1_PSS_PADDING))
                    goto end;
                break;
            default:
                goto end;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            switch (ctx->type) {
            case CKM_RSA_PKCS:
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_PKCSV15))
                    goto end;
                break;
            case  CKM_RSA_PKCS_PSS:
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_PSS))
                    goto end;
                break;
            default:
                goto end;
            }
            break;
        default:
            goto end;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        switch(p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            const char *name = OBJ_nid2sn(ctx->digest_nid);
            if (name == NULL)
                goto end;
            if (!OSSL_PARAM_set_utf8_string(p, name))
                goto end;
        }
        break;
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->digest_nid))
                goto end;
        break;
        default:
            goto end;
        }
    }
    ret = 1;
end:
    return ret;
}

static const OSSL_PARAM *pkcs11_signature_gettable_ctx_params(ossl_unused void *vprsactx,
                                                 ossl_unused void *provctx)
{
    return pkcs11_sign_gettable_ctx_params_tbl;
}

static int pkcs11_signature_set_ctx_params(void *sigctx, const OSSL_PARAM params[])
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    const OSSL_PARAM *p;
    char digestname[80];
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            char *pdigestname = digestname;
            if (OSSL_PARAM_get_utf8_string(p, (char **)&pdigestname, sizeof(digestname))
                    != 1)
                goto end;
            /* Convert digest name into nid */
            if (strlen(digestname) <= 0 || strcmp(digestname, "UNDEF") == 0 ||
                    strcmp(digestname, "undefined") == 0)
                ctx->digest_nid = NID_undef;
            else {
                /* Try short name first, then long name */
                ctx->digest_nid = OBJ_sn2nid(digestname);
                if (ctx->digest_nid == NID_undef)
                    ctx->digest_nid = OBJ_ln2nid(digestname);
                if (ctx->digest_nid == NID_undef)
                    goto end;
            }
        }
            break;
        case OSSL_PARAM_INTEGER: {
            int niddigest = -1;
            if (OSSL_PARAM_get_int(p, &niddigest) != 1)
                goto end;
            ctx->digest_nid = niddigest;
        }
            break;
        }
    }
    
    switch(ctx->type) {
        case CKM_RSA_PKCS:
        case  CKM_RSA_PKCS_PSS:
        {
            int val = 0;
            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PAD_MODE)) != NULL) {
                switch(p->data_type) {
                case OSSL_PARAM_INTEGER:
                    if (OSSL_PARAM_get_int(p, &val) != 1)
                        goto end;
                    switch (val) {
                        case RSA_PKCS1_PADDING:
                            ctx->type = CKM_RSA_PKCS;
                        break;
                        case RSA_PKCS1_PSS_PADDING:
                            ctx->type = CKM_RSA_PKCS_PSS;
                        break;
                        default:
                            goto end;
                    }
                    break;
                case OSSL_PARAM_UTF8_STRING:
                {
                    char name[100];
                    char *pname = name;
                    if (OSSL_PARAM_get_utf8_string(p, &pname, sizeof(name)) != 1)
                        goto end;
                    if (strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                        ctx->type = CKM_RSA_PKCS;
                    else if (strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
                        ctx->type = CKM_RSA_PKCS_PSS;
                    else
                        goto end;
                    break;
                }}
            }
        }
        break;
    }

    ret = 1;
end:

    return ret;
}

static const OSSL_PARAM *pkcs11_signature_settable_ctx_params(void *vprsactx,
                                                 ossl_unused void *provctx)
{
    return pkcs11_sign_settable_ctx_params_tbl;
}

OSSL_ALGORITHM *pkcs11_sign_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
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
            switch(item->type)
            {
            case CKM_RSA_PKCS:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_RSA, id,
                                     pkcs11_rsa_sign_dp_tbl,
                                     pkcs11_signature_algo_description);
                break;
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
