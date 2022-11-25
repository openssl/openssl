#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_ctx.h"

#define PKCS11_DEFAULT_RSA_MODULUS_BITS     2048
#define PKCS11_RSA_DEFAULT_MD               "SHA256"

/* Private functions */
PKCS11_TYPE_DATA_ITEM *pkcs11_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type,
                                            CK_ULONG bits);
int pkcs11_add_attribute(OPENSSL_STACK *stack, CK_ATTRIBUTE_TYPE type,
                         CK_VOID_PTR pValue, CK_ULONG ulValueLen);


/* Internal structures */
typedef struct pkcs11_genctx_st {
    PKCS11_CTX *provctx;
    CK_MECHANISM_TYPE type;
    union {
        struct rsa_st {
            CK_ULONG modulus_bits;
            BIGNUM *public_exponent;
            PKCS11_TYPE_DATA_ITEM *mechdata;
        } rsa;
    };
} PKCS11_GENCTX;

typedef struct pkcs11_key_st {
    PKCS11_GENCTX *genctx;
    CK_OBJECT_HANDLE priv;
    CK_OBJECT_HANDLE pub;
} PKCS11_KEY;

/* required functions */
static OSSL_FUNC_keymgmt_gen_init_fn            pkcs11_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_fn                 pkcs11_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn         pkcs11_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_free_fn                pkcs11_keymgmt_free;
static OSSL_FUNC_keymgmt_has_fn                 pkcs11_keymgmt_has;
/* additional functions */
static OSSL_FUNC_keymgmt_get_params_fn          pkcs11_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn     pkcs11_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn pkcs11_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_set_params_fn      pkcs11_keymgmt_gen_set_params;

const OSSL_DISPATCH rsa_keymgmt_dp_tbl[] = {
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pkcs11_rsa_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        (void (*)(void))pkcs11_keymgmt_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))pkcs11_keymgmt_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pkcs11_keymgmt_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        (void (*)(void))pkcs11_keymgmt_gen_cleanup},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pkcs11_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pkcs11_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*)(void))pkcs11_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pkcs11_keymgmt_has},
    {0, NULL}
};

const OSSL_PARAM pkcs11_rsa_keymgmt_gettable_params_tbl[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM pkcs11_rsa_keymgmt_gen_settable_params_tbl[] = {
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END
};

PKCS11_TYPE_DATA_ITEM *pkcs11_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type,
                                            CK_ULONG bits)
{
    int i = 0;
    int ii = 0;
    PKCS11_SLOT *slot = NULL;
    PKCS11_TYPE_DATA_ITEM *pkeymgmt = NULL;

    for (ii = 0; ii < OPENSSL_sk_num(provctx->slots); ii++) {
        slot = (PKCS11_SLOT *)OPENSSL_sk_value(provctx->slots, ii);
        if (slot->slotid == provctx->sel_slot) {
            for (i = 0; i < OPENSSL_sk_num(slot->keymgmt.items); i++) {
                pkeymgmt = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->keymgmt.items, i);
                if (pkeymgmt->type == type) {
                    if (bits >= pkeymgmt->info.ulMinKeySize
                        && bits <= pkeymgmt->info.ulMaxKeySize)
                        return pkeymgmt;
                }
            }
        }
    }
    return NULL;
}

static void *pkcs11_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    PKCS11_GENCTX *genctx = NULL;
    PKCS11_GENCTX *ret = NULL;

    if (provctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->type = CKM_RSA_PKCS_KEY_PAIR_GEN;
    genctx->rsa.public_exponent = BN_new();
    if (genctx->rsa.public_exponent == NULL)
        goto end;

    if (!BN_set_word(genctx->rsa.public_exponent, RSA_F4))
        goto end;

    genctx->rsa.modulus_bits = PKCS11_DEFAULT_RSA_MODULUS_BITS;
    genctx->provctx = (PKCS11_CTX*)provctx;
    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            BN_free(genctx->rsa.public_exponent);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}

int pkcs11_add_attribute(OPENSSL_STACK *stack, CK_ATTRIBUTE_TYPE type,
                         CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
    CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)OPENSSL_zalloc(sizeof(CK_ATTRIBUTE));
    if (attr == NULL)
        return 0;
    attr->type = type;
    attr->pValue = pValue;
    attr->ulValueLen = ulValueLen;
    if (!OPENSSL_sk_push(stack, attr)){
        OPENSSL_free(attr);
        return 0;
    }
    return 1;
}

static void *pkcs11_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    PKCS11_GENCTX *gctx = (PKCS11_GENCTX*)genctx;
    PKCS11_KEY *key = NULL;
    PKCS11_KEY *ret = NULL;
    CK_MECHANISM_TYPE mechtype = gctx->rsa.mechdata->type;
    CK_MECHANISM mech = {mechtype, NULL, 0};
    CK_BBOOL flag_token;
    CK_BBOOL flag_true = CK_TRUE;
    CK_RV rv = CKR_OK;
    CK_BYTE *pub_exp = NULL;
    int pub_exp_len = 0;
    CK_ATTRIBUTE *pub_tbl = NULL;
    CK_ATTRIBUTE *priv_tbl = NULL;
    size_t pub_tbl_len = 0;
    size_t priv_tbl_len = 0;
    OPENSSL_STACK *pub_stack = NULL;
    OPENSSL_STACK *priv_stack = NULL;
    int i = 0;
    CK_ATTRIBUTE *pattr = NULL;

    pub_stack = OPENSSL_sk_new_null();
    if (pub_stack == NULL)
        goto end;

    priv_stack = OPENSSL_sk_new_null();
    if (priv_stack == NULL)
        goto end;

    pub_exp_len = BN_num_bytes(gctx->rsa.public_exponent);
    if (pub_exp_len == 0) 
        goto end;

    pub_exp = (CK_BYTE*)OPENSSL_zalloc(pub_exp_len);
    if (pub_exp == NULL)
        goto end;

    pub_exp_len = BN_bn2bin(gctx->rsa.public_exponent, pub_exp);
    switch(gctx->type)
    {
    case CKM_RSA_PKCS_KEY_PAIR_GEN: {
        /* Common storage object attributes */
        pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
        /* Common public key attributes */
        pkcs11_add_attribute(pub_stack, CKA_ENCRYPT, &flag_true, sizeof(flag_true));
        pkcs11_add_attribute(pub_stack, CKA_VERIFY, &flag_true, sizeof(flag_true));
        pkcs11_add_attribute(pub_stack, CKA_WRAP, &flag_true, sizeof(flag_true));
        /* RSA public key object attributes  */
        pkcs11_add_attribute(pub_stack, CKA_MODULUS_BITS,
                             &gctx->rsa.modulus_bits, sizeof(gctx->rsa.modulus_bits));
        pkcs11_add_attribute(pub_stack, CKA_PUBLIC_EXPONENT, pub_exp, pub_exp_len);

        /* Common storage object attributes */
        pkcs11_add_attribute(priv_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
        pkcs11_add_attribute(priv_stack, CKA_PRIVATE, &flag_true, sizeof(flag_true));
        /* Common private key attributes */
        pkcs11_add_attribute(priv_stack, CKA_SENSITIVE, &flag_true, sizeof(flag_true));
        pkcs11_add_attribute(priv_stack, CKA_DECRYPT, &flag_true, sizeof(flag_true));
        pkcs11_add_attribute(priv_stack, CKA_SIGN, &flag_true, sizeof(flag_true));
        pkcs11_add_attribute(priv_stack, CKA_UNWRAP, &flag_true, sizeof(flag_true));
        break;
    }
    default:
        goto end;
    }

    /* Check allocation, change more dynamic attribute tables (primes, exponents may need to be added or not */
    pub_tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(pub_stack) * sizeof(CK_ATTRIBUTE));
    if (pub_tbl == NULL)
        goto end;

    pub_tbl_len = OPENSSL_sk_num(pub_stack);
    for (i = 0, pattr = pub_tbl; i < pub_tbl_len; i++, pattr++) {
        memcpy(pattr, OPENSSL_sk_value(pub_stack, i), sizeof(CK_ATTRIBUTE));
    }

    priv_tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(priv_stack) * sizeof(CK_ATTRIBUTE));
    if (priv_tbl == NULL)
        goto end;

    priv_tbl_len = OPENSSL_sk_num(priv_stack);
    for (i = 0, pattr = priv_tbl; i < priv_tbl_len; i++, pattr++)
        memcpy(pattr, OPENSSL_sk_value(priv_stack, i), sizeof(CK_ATTRIBUTE));

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;

    key->genctx = gctx;
    /* Maybe add check if PKCS11 functions are NULL or not */
    rv = gctx->provctx->lib_functions->C_GenerateKeyPair(gctx->provctx->session, &mech,
                                                         pub_tbl, pub_tbl_len,
                                                         priv_tbl, priv_tbl_len,
                                                         &key->pub, &key->priv);
    if (rv != CKR_OK)
        goto end;

    ret = key;
end:
    if (!ret)
        OPENSSL_free(key);
    OPENSSL_free(pub_tbl);
    OPENSSL_free(priv_tbl);
    if (pub_stack != NULL) {
        for (i = 0; i < pub_tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(pub_stack));
        OPENSSL_sk_free(pub_stack);
    }
    if (priv_stack != NULL) {
        for (i = 0; i < priv_tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(priv_stack));
        OPENSSL_sk_free(priv_stack);
    }
    if (pub_exp)
        OPENSSL_free(pub_exp);

    return ret;
}

static void pkcs11_keymgmt_gen_cleanup(void *genctx)
{
    PKCS11_GENCTX *ctx = genctx;

    if (ctx != NULL) {
        BN_free(ctx->rsa.public_exponent);
        OPENSSL_free(ctx);
    }
}

static void pkcs11_keymgmt_free(void *keydata)
{
    PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    PKCS11_CTX *ctx = NULL;

    if (key != NULL) {
        ctx = key->genctx->provctx;
        if (ctx != NULL) {
            if (key->priv)
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->priv);
            if (key->pub)
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->pub);
        }
        OPENSSL_free(key);
    }
}

static int pkcs11_keymgmt_has(const void *keydata, int selection)
{
    const PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    int ok = 0;

    if (key == NULL)
        return 0;
    /* WB study that, looks wrong. Check the rsa_keymgmt */
    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                      | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) != 0)
        ok = 1;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE)
                && (key->priv != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key->priv != CK_INVALID_HANDLE);

    return ok;
}

static int pkcs11_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
         && !OSSL_PARAM_set_int(p, key->genctx->rsa.modulus_bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
         && !OSSL_PARAM_set_int(p, (key->genctx->rsa.modulus_bits + 7) / 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, PKCS11_RSA_DEFAULT_MD))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *pkcs11_keymgmt_gettable_params(void *provctx)
{
    return pkcs11_rsa_keymgmt_gettable_params_tbl;
}

static const OSSL_PARAM *pkcs11_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    return pkcs11_rsa_keymgmt_gen_settable_params_tbl;
}

static int pkcs11_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    PKCS11_GENCTX *ctx = (PKCS11_GENCTX *)genctx;
    const OSSL_PARAM *p;
    PKCS11_CTX *provctx = NULL;
    PKCS11_TYPE_DATA_ITEM *found = NULL;
    size_t bits = 0;
    int ret = 0;

    provctx = ctx->provctx;
    if (ctx->type == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
            if (OSSL_PARAM_get_size_t(p, &bits) != 1)
                goto end;

            /* Find a fitting key manager mechanism */
            found = pkcs11_get_mech_data(provctx, CKM_RSA_PKCS_KEY_PAIR_GEN, bits);
            if (!found)
                goto end;

            ctx->rsa.mechdata = found;
            ctx->rsa.modulus_bits = bits;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
            if (!OSSL_PARAM_get_BN(p, &ctx->rsa.public_exponent))
                goto end;
        }
    }
    ret = 1;
end:
    return ret;
}

