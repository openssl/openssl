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

#define PKCS11_DEFAULT_RSA_MODULUS_BITS     2048
#define PKCS11_RSA_DEFAULT_MD               "SHA256"
#define PKCS11_ECDSA_DEFAUL_NAME            "secp224r1"
#define PKCS11_KEYMGMT_ALGO_DESCRIPTION     "PKSC11 keymgmt algo"

static char* pkcs11_keymgmt_algo_description = PKCS11_KEYMGMT_ALGO_DESCRIPTION;
static char* pkcs11_keymgmt_rsa_algo_description = "PKSC11 keymgmt rsa algo";
/* Private functions */
PKCS11_TYPE_DATA_ITEM *pkcs11_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type,
                                            CK_ULONG bits);
static int pkcs11_set_ec_oid_name(CK_BYTE_PTR *pp, const char *name);

/* required functions */
static OSSL_FUNC_keymgmt_gen_init_fn            pkcs11_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn            pkcs11_dsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn            pkcs11_ecdsa_keymgmt_gen_init;
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

const OSSL_DISPATCH dsa_keymgmt_dp_tbl[] = {
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pkcs11_dsa_keymgmt_gen_init},
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

const OSSL_DISPATCH ecdsa_keymgmt_dp_tbl[] = {
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pkcs11_ecdsa_keymgmt_gen_init},
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

const OSSL_PARAM pkcs11_keymgmt_gettable_params_tbl[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM pkcs11_keymgmt_gen_settable_params_tbl[] = {
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL), /* RSA */
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),     /* DSA */
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),     /* ECDSA */
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    PKCS11_KEYMGMT_CTX *genctx = NULL;
    PKCS11_KEYMGMT_CTX *ret = NULL;

    if (provctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->type = CKM_RSA_PKCS_KEY_PAIR_GEN;
    genctx->keyparam.rsa.public_exponent = BN_new();
    if (genctx->keyparam.rsa.public_exponent == NULL)
        goto end;

    if (!BN_set_word(genctx->keyparam.rsa.public_exponent, RSA_F4))
        goto end;

    genctx->keyparam.rsa.modulus_bits = PKCS11_DEFAULT_RSA_MODULUS_BITS;
    genctx->keyparam.rsa.mechdata = pkcs11_get_mech_data((PKCS11_CTX *)provctx, genctx->type, PKCS11_DEFAULT_RSA_MODULUS_BITS);
    if (!genctx->keyparam.rsa.mechdata)
        goto end;

    genctx->pkcs11_ctx = (PKCS11_CTX *)provctx;
    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            BN_free(genctx->keyparam.rsa.public_exponent);
            OPENSSL_free(genctx);
        }
    }
    fprintf(stdout, "@@ %s %p\n", __FUNCTION__, ret);
    fflush(stdout);
    return ret;
}

static void *pkcs11_dsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    PKCS11_KEYMGMT_CTX *genctx = NULL;
    PKCS11_KEYMGMT_CTX *ret = NULL;

    if (provctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->type = CKM_DSA_KEY_PAIR_GEN;
    genctx->keyparam.dsa.p = BN_new();
    if (genctx->keyparam.dsa.p == NULL)
        goto end;

    genctx->keyparam.dsa.q = BN_new();
    if (genctx->keyparam.dsa.q == NULL)
        goto end;

    genctx->keyparam.dsa.g = BN_new();
    if (genctx->keyparam.dsa.g == NULL)
        goto end;

    genctx->keyparam.dsa.mechdata = pkcs11_get_mech_data((PKCS11_CTX *)provctx, genctx->type, 0);
    if (!genctx->keyparam.rsa.mechdata)
        goto end;

    genctx->pkcs11_ctx = (PKCS11_CTX *)provctx;
    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            BN_free(genctx->keyparam.dsa.p);
            BN_free(genctx->keyparam.dsa.q);
            BN_free(genctx->keyparam.dsa.g);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}


static void *pkcs11_ecdsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    PKCS11_KEYMGMT_CTX *genctx = NULL;
    PKCS11_KEYMGMT_CTX *ret = NULL;

    if (provctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->type = CKM_ECDSA_KEY_PAIR_GEN;
    genctx->keyparam.ecdsa.oid_name_len = pkcs11_set_ec_oid_name(&genctx->keyparam.ecdsa.oid_name, PKCS11_ECDSA_DEFAUL_NAME);
    if (genctx->keyparam.ecdsa.oid_name == NULL)
        goto end;

    genctx->keyparam.ecdsa.mechdata = pkcs11_get_mech_data((PKCS11_CTX *)provctx, genctx->type, 0);
    if (!genctx->keyparam.ecdsa.mechdata)
        goto end;

    genctx->pkcs11_ctx = (PKCS11_CTX *)provctx;
    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            OPENSSL_free(genctx->keyparam.ecdsa.oid_name);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}

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
                    if (bits > 0) {
                        if (bits >= pkeymgmt->info.ulMinKeySize
                            && bits <= pkeymgmt->info.ulMaxKeySize)
                            return pkeymgmt;
                        continue;
                    }
                    return pkeymgmt;
                }
            }
        }
    }
    return NULL;
}

static void *pkcs11_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    PKCS11_KEYMGMT_CTX *gctx = (PKCS11_KEYMGMT_CTX*)genctx;
    PKCS11_KEY *key = NULL;
    PKCS11_KEY *ret = NULL;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_BBOOL flag_token;
    CK_BBOOL flag_true = CK_TRUE;
    CK_RV rv = CKR_OK;
    /* rsa */
    CK_BYTE *pub_exp = NULL;
    int pub_exp_len = 0;
    /* dsa */
    CK_BYTE *p = NULL;
    int p_len = 0;
    CK_BYTE *q = NULL;
    int q_len = 0;
    CK_BYTE *g = NULL;
    int g_len = 0;
    CK_ATTRIBUTE *pub_tbl = NULL;
    CK_ATTRIBUTE *priv_tbl = NULL;
    size_t pub_tbl_len = 0;
    size_t priv_tbl_len = 0;
    OPENSSL_STACK *pub_stack = NULL;
    OPENSSL_STACK *priv_stack = NULL;
    int i = 0;
    CK_ATTRIBUTE *pattr = NULL;

    switch(gctx->type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        mech.mechanism = gctx->keyparam.rsa.mechdata->type;
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        mech.mechanism = gctx->keyparam.dsa.mechdata->type;
        break;
    case CKM_ECDSA_KEY_PAIR_GEN:
        mech.mechanism = gctx->keyparam.ecdsa.mechdata->type;
        break;
    default:
        goto end;
    }
    pub_stack = OPENSSL_sk_new_null();
    if (pub_stack == NULL)
        goto end;

    priv_stack = OPENSSL_sk_new_null();
    if (priv_stack == NULL)
        goto end;

    switch(gctx->type)
    {
    case CKM_RSA_PKCS_KEY_PAIR_GEN: {
            if ((pub_exp_len = pkcs11_get_byte_array(gctx->keyparam.rsa.public_exponent,
                                                     &pub_exp)) < 0)
                goto end;
            /* Common storage object attributes */
            pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            /* Common public key attributes */
            pkcs11_add_attribute(pub_stack, CKA_ENCRYPT, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(pub_stack, CKA_VERIFY, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(pub_stack, CKA_WRAP, &flag_true, sizeof(flag_true));
            /* RSA public key object attributes  */
            pkcs11_add_attribute(pub_stack, CKA_MODULUS_BITS, 
                                 &gctx->keyparam.rsa.modulus_bits, 
                                 sizeof(gctx->keyparam.rsa.modulus_bits));
            pkcs11_add_attribute(pub_stack, CKA_PUBLIC_EXPONENT, pub_exp, pub_exp_len);
            /* Common storage object attributes */
            pkcs11_add_attribute(priv_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            pkcs11_add_attribute(priv_stack, CKA_PRIVATE, &flag_true, sizeof(flag_true));
            /* Common private key attributes */
            pkcs11_add_attribute(priv_stack, CKA_SENSITIVE, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_DECRYPT, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_SIGN, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_UNWRAP, &flag_true, sizeof(flag_true));
        }
        break;
    case CKM_DSA_KEY_PAIR_GEN: {
            if ((p_len = pkcs11_get_byte_array(gctx->keyparam.dsa.p, &p)) < 0)
                goto end;
            if ((q_len = pkcs11_get_byte_array(gctx->keyparam.dsa.q, &q)) < 0)
                goto end;
            if ((g_len = pkcs11_get_byte_array(gctx->keyparam.dsa.g, &g)) < 0)
                goto end;
            pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            /* RSA public key object attributes  */
            pkcs11_add_attribute(pub_stack, CKA_BASE, g, g_len);
            pkcs11_add_attribute(pub_stack, CKA_PRIME, p, p_len);
            pkcs11_add_attribute(pub_stack, CKA_SUBPRIME, q, q_len);
        }
    case CKM_ECDSA_KEY_PAIR_GEN: {
            /* Common storage object attributes */
            pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            /* Common public key attributes */
            pkcs11_add_attribute(pub_stack, CKA_EC_PARAMS, gctx->keyparam.ecdsa.oid_name,
                                 gctx->keyparam.ecdsa.oid_name_len);
            /* Common storage object attributes */
            pkcs11_add_attribute(priv_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            pkcs11_add_attribute(priv_stack, CKA_PRIVATE, &flag_true, sizeof(flag_true));
            /* Common private key attributes */
            pkcs11_add_attribute(priv_stack, CKA_SENSITIVE, &flag_true, sizeof(flag_true));
        }
        break;
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

    key->keymgmt_ctx = gctx;
    /* Maybe add check if PKCS11 functions are NULL or not */
    rv = gctx->pkcs11_ctx->lib_functions->C_GenerateKeyPair(gctx->pkcs11_ctx->session, &mech,
                                                         pub_tbl, pub_tbl_len,
                                                         priv_tbl, priv_tbl_len,
                                                         &key->pub, &key->priv);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(gctx->pkcs11_ctx, rv);
        goto end;
    }

    fprintf(stdout, "@@@ provider: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)gctx->pkcs11_ctx->ctx.handle));
    fprintf(stdout, "@@@ - Pubkey = %lu\n", key->pub);
    fprintf(stdout, "@@@ - Privkey = %lu\n", key->priv);
    fprintf(stdout, "@@@ - lib_functions ptr %p\n", gctx->pkcs11_ctx->lib_functions);
    fflush(stdout);

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
    if (p)
        OPENSSL_free(p);
    if (q)
        OPENSSL_free(q);
    if (g)
        OPENSSL_free(g);

    return ret;
}

static void pkcs11_keymgmt_gen_cleanup(void *genctx)
{
    PKCS11_KEYMGMT_CTX *ctx = (PKCS11_KEYMGMT_CTX *)genctx;

    if (ctx != NULL) {
        switch(ctx->type)
        {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            BN_free(ctx->keyparam.rsa.public_exponent);
            break;
        case CKM_DSA_KEY_PAIR_GEN:
            BN_free(ctx->keyparam.dsa.p);
            BN_free(ctx->keyparam.dsa.q);
            BN_free(ctx->keyparam.dsa.g);
            break;
        case CKM_ECDSA_KEY_PAIR_GEN:
            OPENSSL_free(ctx->keyparam.ecdsa.oid_name);
            break;
        }
        OPENSSL_free(ctx);
    }
}

static void pkcs11_keymgmt_free(void *keydata)
{
    PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    PKCS11_CTX *ctx = NULL;

    if (key != NULL) {
        ctx = key->keymgmt_ctx->pkcs11_ctx;
        if (ctx != NULL) {
            fprintf(stdout, "@@@ provider: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
            fprintf(stdout, "@@@ - lib_functions ptr %p\n", ctx->lib_functions);
            if (key->pub) {
                fprintf(stdout, "@@@ - Free Pubkey = %lu\n", key->pub);
                fflush(stdout);
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->pub);
            }
            key->pub = 0;
            if (key->priv) {
                fprintf(stdout, "@@@ - Free Privkey = %lu\n", key->priv);
                fflush(stdout);
                (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->priv);
            }
            key->priv = 0;
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

    if ((selection & 
         (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) == 0)
        return 1; /* the selection is not missing */

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
         && !OSSL_PARAM_set_int(p, key->keymgmt_ctx->keyparam.rsa.modulus_bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
         && !OSSL_PARAM_set_int(p, (key->keymgmt_ctx->keyparam.rsa.modulus_bits + 7) / 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, PKCS11_RSA_DEFAULT_MD))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *pkcs11_keymgmt_gettable_params(void *provctx)
{
    return pkcs11_keymgmt_gettable_params_tbl;
}

static const OSSL_PARAM *pkcs11_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    return pkcs11_keymgmt_gen_settable_params_tbl;
}

static int pkcs11_set_ec_oid_name(CK_BYTE_PTR *pp, const char *name)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(name, 0);
    CK_BYTE_PTR pparam = NULL;
    int ret = 0;

    if (obj == NULL)
        goto end;
    /* OBJ_nid2obj
     * OBJ_get0_data(const ASN1_OBJECT *obj)*/
    if (pp == NULL)
        goto end;
    (*pp) = OPENSSL_zalloc(OBJ_length(obj) + 2);
    if ((*pp) == NULL)
        goto end;
    ret = OBJ_length(obj) + 2;
    pparam = (*pp);
    *pparam = 0x06;
    pparam++;
    *pparam = OBJ_length(obj);
    pparam++;
    memcpy(pparam, OBJ_get0_data(obj), OBJ_length(obj));
end:
    return ret;
}

static int pkcs11_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    PKCS11_KEYMGMT_CTX *ctx = (PKCS11_KEYMGMT_CTX *)genctx;
    const OSSL_PARAM *p;
    PKCS11_CTX *provctx = NULL;
    PKCS11_TYPE_DATA_ITEM *found = NULL;
    size_t bits = 0;
    int ret = 0;
    const char *strval;

    provctx = ctx->pkcs11_ctx;
    switch(ctx->type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
            if (OSSL_PARAM_get_size_t(p, &bits) != 1)
                goto end;

            /* Find a fitting key manager mechanism */
            found = pkcs11_get_mech_data(provctx, CKM_RSA_PKCS_KEY_PAIR_GEN, bits);
            if (!found)
                goto end;

            ctx->keyparam.rsa.mechdata = found;
            ctx->keyparam.rsa.modulus_bits = bits;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
            if (!OSSL_PARAM_get_BN(p, &ctx->keyparam.rsa.public_exponent))
                goto end;
        }
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P)) != NULL) {
            if (!OSSL_PARAM_get_BN(p, &ctx->keyparam.dsa.p))
                goto end;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G)) != NULL) {
            if (!OSSL_PARAM_get_BN(p, &ctx->keyparam.dsa.g))
                goto end;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q)) != NULL) {
            if (!OSSL_PARAM_get_BN(p, &ctx->keyparam.dsa.q))
                goto end;
        }
        break;
    case CKM_ECDSA_KEY_PAIR_GEN:
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
            if (!OSSL_PARAM_get_utf8_ptr(p, &strval))
                goto end;
            else {
                if (ctx->keyparam.ecdsa.oid_name != NULL)
                    OPENSSL_free(ctx->keyparam.ecdsa.oid_name);
                ctx->keyparam.ecdsa.oid_name_len = pkcs11_set_ec_oid_name(&ctx->keyparam.ecdsa.oid_name, strval);
            }
        }
        break;
    default:
        return 0;
    }
    ret = 1;
end:
    return ret;
}

OSSL_ALGORITHM *pkcs11_keymgmt_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
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
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_RSA, id, rsa_keymgmt_dp_tbl, pkcs11_keymgmt_rsa_algo_description);
                break;
            case CKM_DSA_KEY_PAIR_GEN:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_DSA, id, dsa_keymgmt_dp_tbl, pkcs11_keymgmt_algo_description);
                break;
            case CKM_DH_PKCS_KEY_PAIR_GEN:
                break;
            case CKM_ECDSA_KEY_PAIR_GEN:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_ECDSA, id, ecdsa_keymgmt_dp_tbl, pkcs11_keymgmt_algo_description);
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
