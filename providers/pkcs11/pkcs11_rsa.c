#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "prov/providercommon.h"
#include <openssl/core_dispatch.h>
#include "prov/names.h"
#include <openssl/params.h> /*XXX will eventually be provided by the core*/
#include "pkcs11_ctx.h"

#define PKCS11_DEFAULT_RSA_PUBLIC_EXPONENTS {0x01, 0x00, 0x01}
#define PKCS11_DEFAULT_RSA_MODULUS_BITS     2048


/* required functions */
static OSSL_FUNC_keymgmt_gen_init_fn pkcs11_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_fn rsa_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn rsa_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_free_fn rsa_keymgmt_free;
static OSSL_FUNC_keymgmt_has_fn rsa_keymgmt_has;
/* additional functions */
static OSSL_FUNC_keymgmt_get_params_fn rsa_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn rsa_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn rsa_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_set_params_fn rsa_keymgmt_gen_set_params;

const OSSL_DISPATCH rsa_keymgmt_dp_tbl[] = {
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pkcs11_rsa_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        (void (*)(void))rsa_keymgmt_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))rsa_keymgmt_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_keymgmt_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        (void (*)(void))rsa_keymgmt_gen_cleanup},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*)(void))rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))rsa_keymgmt_has},
    {0, NULL}
};

struct pkcs11_genctx_st {
    PKCS11_CTX *provctx;
    CK_MECHANISM_TYPE type;
};

struct pkcs11_rsa_genctx_st {
    struct pkcs11_genctx_st ctx;
    CK_ULONG modulus_bits;
    CK_BYTE *public_exponent;
    CK_ULONG public_exponentlen;
    PKCS11_TYPE_DATA_ITEM *mechdata;
};

struct pkcs11_rsa_keykey_st {
    struct pkcs11_rsa_genctx_st* genctx;
    CK_OBJECT_HANDLE priv;
    CK_OBJECT_HANDLE pub;
};

static void *pkcs11_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    static const CK_BYTE public_exponent[] = PKCS11_DEFAULT_RSA_PUBLIC_EXPONENTS;
    struct pkcs11_rsa_genctx_st *genctx = NULL;
    struct pkcs11_rsa_genctx_st *ret = NULL;

    if (!provctx)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->ctx.type = CKM_RSA_PKCS_KEY_PAIR_GEN;
    genctx->public_exponentlen = sizeof(public_exponent);
    genctx->public_exponent = OPENSSL_zalloc(genctx->public_exponentlen);
    if (genctx->public_exponent == NULL)
        goto end;

    memcpy(genctx->public_exponent,
           public_exponent, genctx->public_exponentlen);
    genctx->modulus_bits = PKCS11_DEFAULT_RSA_MODULUS_BITS;
    genctx->ctx.provctx = (PKCS11_CTX*)provctx;
    ret = genctx;

end:
    if (!ret)
    {
        if (genctx){
            if (genctx->public_exponent)
                OPENSSL_free(genctx->public_exponent);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}

# define NMEMB(array) (sizeof(array) / sizeof(array[0]))
static void *rsa_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    struct pkcs11_rsa_genctx_st *gctx = genctx;
    struct pkcs11_rsa_keykey_st *key = NULL;
    struct pkcs11_rsa_keykey_st *ret = NULL;
    CK_MECHANISM_TYPE mechtype = gctx->mechdata->type;
    CK_MECHANISM mech = {mechtype, NULL, 0};
    CK_BBOOL flag_token; /* = ctx->provctx->tokobjs;*/
    CK_BBOOL flag_true = CK_TRUE;
    CK_RV rv = CKR_OK;

    CK_ATTRIBUTE pub_templ[] = {
        /* Common storage object attributes */
        {CKA_TOKEN, &flag_token, sizeof(flag_token)},
        /* Common public key attributes */
        {CKA_ENCRYPT, &flag_true, sizeof(flag_true)},
        {CKA_VERIFY, &flag_true, sizeof(flag_true)},
        {CKA_WRAP, &flag_true, sizeof(flag_true)},
        /* RSA public key object attributes  */
        {CKA_MODULUS_BITS,
         &gctx->modulus_bits, sizeof(gctx->modulus_bits)}, /* required */
        {CKA_PUBLIC_EXPONENT,
         gctx->public_exponent, gctx->public_exponentlen}
    };
    CK_ATTRIBUTE priv_templ[] = {
        /* Common storage object attributes */
        {CKA_TOKEN, &flag_token, sizeof(flag_token)},
        {CKA_PRIVATE, &flag_true, sizeof(flag_true)},
        /* Common private key attributes */
        {CKA_SENSITIVE, &flag_true, sizeof(flag_true)},
        {CKA_DECRYPT, &flag_true, sizeof(flag_true)},
        {CKA_SIGN, &flag_true, sizeof(flag_true)},
        {CKA_UNWRAP, &flag_true, sizeof(flag_true)},
    };

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;

    key->genctx = gctx;
    rv = gctx->ctx.provctx->lib_functions->C_GenerateKeyPair(gctx->ctx.provctx->session, &mech,
                                             pub_templ, NMEMB(pub_templ),
                                             priv_templ, NMEMB(priv_templ),
                                             &key->pub, &key->priv);
    if (rv != CKR_OK)
        goto end;

    ret = key;
end:
    if (!ret)
    {
        OPENSSL_free(key);
    }
    return ret;
}

static void rsa_keymgmt_gen_cleanup(void *genctx)
{
    struct pkcs11_rsa_genctx_st *ctx = genctx;

    assert(genctx != NULL);

    OPENSSL_free(ctx->public_exponent);
    OPENSSL_free(ctx);
}

static void rsa_keymgmt_free(void *keydata)
{
    struct pkcs11_rsa_keykey_st *key = keydata;
    PKCS11_CTX *ctx;

    if (key == NULL)
        return;

    ctx = key->genctx->ctx.provctx;

    (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->priv);
    (void)ctx->lib_functions->C_DestroyObject(ctx->session, key->pub);
    OPENSSL_free(key);
}

static int rsa_keymgmt_has(const void *keydata, int selection)
{
    const struct pkcs11_rsa_keykey_st *key = keydata;
    int ok = 0;

    assert(keydata != NULL);

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                      | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && 0;     /* XXX will change with PSS and OAEP */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE)
                && (key->priv != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (key->pub != CK_INVALID_HANDLE);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (key->priv != CK_INVALID_HANDLE);

    return ok;
}

static int rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    struct pkcs11_rsa_keykey_st *key = keydata;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, key->genctx->modulus_bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, (key->genctx->modulus_bits + 7) / 8))
        return 0;
# if 0  /* XXX PSS */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
       ) {
    }
#endif
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
            ) {
        if (!OSSL_PARAM_set_utf8_string(p, "SHA256")) /* XXX PSS */
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *rsa_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM rsa_keymgmt_gettable_params_tbl[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return rsa_keymgmt_gettable_params_tbl;
}

static const OSSL_PARAM *rsa_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM rsa_keymgmt_gen_settable_params_tbl[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return rsa_keymgmt_gen_settable_params_tbl;
}

static int rsa_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct pkcs11_rsa_genctx_st *ctx = genctx;
    const OSSL_PARAM *p;
    PKCS11_CTX *provctx = NULL;
    PKCS11_TYPE_DATA_ITEM* pkeymgmt = NULL;
    PKCS11_TYPE_DATA_ITEM* found = NULL;
    CK_ULONG bits;
    int i = 0;
    int rc;
    int ret = 0;

    provctx = ctx->ctx.provctx;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        if (OSSL_PARAM_get_size_t(p, &bits) != 1)
            goto end;

        /* Find a fitting key manager mechanism */
        pkeymgmt = provctx->keymgmt.items;
        for (i = 0; i < provctx->keymgmt.len; i++, pkeymgmt++)
        {
            if (pkeymgmt->type == CKM_RSA_PKCS_KEY_PAIR_GEN)
            {
                if (bits >= pkeymgmt->info.ulMinKeySize
                   && bits <= pkeymgmt->info.ulMaxKeySize)
                {
                    found = pkeymgmt;
                    break;
                }
            }
        }
        if (!found)
            goto end;

        ctx->mechdata = found;
        ctx->modulus_bits = bits;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
        const union {
            long one;
            char little;
        } is_endian = { 1 };
        unsigned char *buf = p->data;
        size_t buflen = p->data_size;

        if (is_endian.little == 1)
        {
            /* skip trainling zeros */
            for (buf += p->data_size - 1;
                 *buf == 0 && buflen > 0; buf--, buflen--)
                ;
            buf = p->data;
        }
        else
        {
            /* skip leading zeros */
            for (buf = p->data; *buf == 0 && buflen > 0; buf++, buflen--)
                ;
        }

        ctx->public_exponentlen = buflen;
        ctx->public_exponent = realloc(ctx->public_exponent, buflen);
        if (ctx->public_exponent == NULL)
            return 0;

        if (is_endian.little == 1) {
            size_t i;

            for (i = 0; i < buflen; i++) {
                ctx->public_exponent[i] = buf[buflen - 1 - i];
            }
        }
        else
        {
            memcpy(ctx->public_exponent, buf, buflen);
        }
    }
    ret = 1;
end:
    return ret;
}

