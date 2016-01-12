/**********************************************************************
 *                          gost_crypt.c                              *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST 28147-89 cipher functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include "gost89.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include "e_gost_err.h"
#include "gost_lcl.h"
#include <openssl/evp.h>

#if !defined(CCGOST_DEBUG) && !defined(DEBUG)
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

static int gost_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc);
static int gost_cipher_init_cpa(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc);
/* Handles block of data in CFB mode */
static int gost_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl);
/* Handles block of data in CNT mode */
static int gost_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl);
/* Cleanup function */
static int gost_cipher_cleanup(EVP_CIPHER_CTX *);
/* set/get cipher parameters */
static int gost89_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params);
static int gost89_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params);
/* Control function */
static int gost_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static EVP_CIPHER *_hidden_Gost28147_89_cipher = NULL;
const EVP_CIPHER *cipher_gost(void)
{
    if (_hidden_Gost28147_89_cipher == NULL
        && ((_hidden_Gost28147_89_cipher =
             EVP_CIPHER_meth_new(NID_id_Gost28147_89,
                                 1  /* block_size */,
                                 32 /* key_size */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_Gost28147_89_cipher, 8)
            || !EVP_CIPHER_meth_set_flags(_hidden_Gost28147_89_cipher,
                                          EVP_CIPH_CFB_MODE |
                                          EVP_CIPH_NO_PADDING |
                                          EVP_CIPH_CUSTOM_IV |
                                          EVP_CIPH_RAND_KEY |
                                          EVP_CIPH_ALWAYS_CALL_INIT)
            || !EVP_CIPHER_meth_set_init(_hidden_Gost28147_89_cipher,
                                         gost_cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_Gost28147_89_cipher,
                                              gost_cipher_do_cfb)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_Gost28147_89_cipher,
                                            gost_cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_Gost28147_89_cipher,
                                                  sizeof(struct ossl_gost_cipher_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_Gost28147_89_cipher,
                                                    gost89_set_asn1_parameters)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_Gost28147_89_cipher,
                                                    gost89_get_asn1_parameters)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_Gost28147_89_cipher,
                                         gost_cipher_ctl))) {
        EVP_CIPHER_meth_free(_hidden_Gost28147_89_cipher);
        _hidden_Gost28147_89_cipher = NULL;
    }
    return _hidden_Gost28147_89_cipher;
}

static EVP_CIPHER *_hidden_gost89_cnt = NULL;
const EVP_CIPHER *cipher_gost_cpacnt(void)
{
    if (_hidden_gost89_cnt == NULL
        && ((_hidden_gost89_cnt =
             EVP_CIPHER_meth_new(NID_gost89_cnt,
                                 1  /* block_size */,
                                 32 /* key_size */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_gost89_cnt, 8)
            || !EVP_CIPHER_meth_set_flags(_hidden_gost89_cnt,
                                          EVP_CIPH_OFB_MODE |
                                          EVP_CIPH_NO_PADDING |
                                          EVP_CIPH_CUSTOM_IV |
                                          EVP_CIPH_RAND_KEY |
                                          EVP_CIPH_ALWAYS_CALL_INIT)
            || !EVP_CIPHER_meth_set_init(_hidden_gost89_cnt,
                                         gost_cipher_init_cpa)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_gost89_cnt,
                                              gost_cipher_do_cnt)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_gost89_cnt,
                                            gost_cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_gost89_cnt,
                                                  sizeof(struct ossl_gost_cipher_ctx))
            || !EVP_CIPHER_meth_set_set_asn1_params(_hidden_gost89_cnt,
                                                    gost89_set_asn1_parameters)
            || !EVP_CIPHER_meth_set_get_asn1_params(_hidden_gost89_cnt,
                                                    gost89_get_asn1_parameters)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_gost89_cnt,
                                         gost_cipher_ctl))) {
        EVP_CIPHER_meth_free(_hidden_gost89_cnt);
        _hidden_gost89_cnt = NULL;
    }
    return _hidden_gost89_cnt;
}

/* Implementation of GOST 28147-89 in MAC (imitovstavka) mode */
/* Init functions which set specific parameters */
static int gost_imit_init_cpa(EVP_MD_CTX *ctx);
/* process block of data */
static int gost_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count);
/* Return computed value */
static int gost_imit_final(EVP_MD_CTX *ctx, unsigned char *md);
/* Copies context */
static int gost_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_imit_cleanup(EVP_MD_CTX *ctx);
/* Control function, knows how to set MAC key.*/
static int gost_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr);

static EVP_MD *_hidden_Gost28147_89_MAC_md = NULL;
const EVP_MD *imit_gost_cpa(void)
{

    if (_hidden_Gost28147_89_MAC_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_id_Gost28147_89_MAC, NID_undef)) == NULL
            || !EVP_MD_meth_set_result_size(md, 4)
            || !EVP_MD_meth_set_input_blocksize(md, 8)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(struct ossl_gost_imit_ctx))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, gost_imit_init_cpa)
            || !EVP_MD_meth_set_update(md, gost_imit_update)
            || !EVP_MD_meth_set_final(md, gost_imit_final)
            || !EVP_MD_meth_set_copy(md, gost_imit_copy)
            || !EVP_MD_meth_set_cleanup(md, gost_imit_cleanup)
            || !EVP_MD_meth_set_ctrl(md, gost_imit_ctrl)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_Gost28147_89_MAC_md = md;
    }
    return _hidden_Gost28147_89_MAC_md;
}
void imit_gost_cpa_destroy(void)
{
    EVP_MD_meth_free(_hidden_Gost28147_89_MAC_md);
    _hidden_Gost28147_89_MAC_md = NULL;
}

/*
 * Correspondence between gost parameter OIDs and substitution blocks
 * NID field is filed by register_gost_NID function in engine.c
 * upon engine initialization
 */

struct gost_cipher_info gost_cipher_list[] = {
    /*- NID *//*
     * Subst block
     *//*
     * Key meshing
     */
    /*
     * {NID_id_GostR3411_94_CryptoProParamSet,&GostR3411_94_CryptoProParamSet,0},
     */
    {NID_id_Gost28147_89_CryptoPro_A_ParamSet, &Gost28147_CryptoProParamSetA,
     1},
    {NID_id_Gost28147_89_CryptoPro_B_ParamSet, &Gost28147_CryptoProParamSetB,
     1},
    {NID_id_Gost28147_89_CryptoPro_C_ParamSet, &Gost28147_CryptoProParamSetC,
     1},
    {NID_id_Gost28147_89_CryptoPro_D_ParamSet, &Gost28147_CryptoProParamSetD,
     1},
    {NID_id_Gost28147_89_TestParamSet, &Gost28147_TestParamSet, 1},
    {NID_undef, NULL, 0}
};

/*
 * get encryption parameters from crypto network settings FIXME For now we
 * use environment var CRYPT_PARAMS as place to store these settings.
 * Actually, it is better to use engine control command, read from
 * configuration file to set them
 */
const struct gost_cipher_info *get_encryption_params(ASN1_OBJECT *obj)
{
    int nid;
    struct gost_cipher_info *param;
    if (!obj) {
        const char *params = get_gost_engine_param(GOST_PARAM_CRYPT_PARAMS);
        if (!params || !strlen(params))
            return &gost_cipher_list[1];

        nid = OBJ_txt2nid(params);
        if (nid == NID_undef) {
            GOSTerr(GOST_F_GET_ENCRYPTION_PARAMS,
                    GOST_R_INVALID_CIPHER_PARAM_OID);
            return NULL;
        }
    } else {
        nid = OBJ_obj2nid(obj);
    }
    for (param = gost_cipher_list; param->sblock != NULL && param->nid != nid;
         param++) ;
    if (!param->sblock) {
        GOSTerr(GOST_F_GET_ENCRYPTION_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return NULL;
    }
    return param;
}

/* Sets cipher param from paramset NID. */
static int gost_cipher_set_param(struct ossl_gost_cipher_ctx *c, int nid)
{
    const struct gost_cipher_info *param;
    param =
        get_encryption_params((nid == NID_undef ? NULL : OBJ_nid2obj(nid)));
    if (!param)
        return 0;

    c->paramNID = param->nid;
    c->key_meshing = param->key_meshing;
    c->count = 0;
    gost_init(&(c->cctx), param->sblock);
    return 1;
}

/* Initializes EVP_CIPHER_CTX by paramset NID */
static int gost_cipher_init_param(EVP_CIPHER_CTX *ctx,
                                  const unsigned char *key,
                                  const unsigned char *iv, int enc,
                                  int paramNID, int mode)
{
    struct ossl_gost_cipher_ctx *c = EVP_CIPHER_CTX_cipher_data(ctx);
    if (EVP_CIPHER_CTX_get_app_data(ctx) == NULL) {
        if (!gost_cipher_set_param(c, paramNID))
            return 0;
        EVP_CIPHER_CTX_set_app_data(ctx, EVP_CIPHER_CTX_cipher_data(ctx));
    }
    if (key)
        gost_key(&(c->cctx), key);
    if (iv)
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
           EVP_CIPHER_CTX_original_iv(ctx),
           EVP_CIPHER_CTX_iv_length(ctx));
    return 1;
}

static int gost_cipher_init_cpa(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc)
{
    struct ossl_gost_cipher_ctx *c = EVP_CIPHER_CTX_cipher_data(ctx);
    gost_init(&(c->cctx), &Gost28147_CryptoProParamSetA);
    c->key_meshing = 1;
    c->count = 0;
    if (key)
        gost_key(&(c->cctx), key);
    if (iv)
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
           EVP_CIPHER_CTX_original_iv(ctx),
           EVP_CIPHER_CTX_iv_length(ctx));
    return 1;
}

/* Initializes EVP_CIPHER_CTX with default values */
int gost_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    return gost_cipher_init_param(ctx, key, iv, enc, NID_undef,
                                  EVP_CIPH_CFB_MODE);
}

/*
 * Wrapper around gostcrypt function from gost89.c which perform key meshing
 * when nesseccary
 */
static void gost_crypt_mesh(void *ctx, unsigned char *iv, unsigned char *buf)
{
    struct ossl_gost_cipher_ctx *c = ctx;
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), iv);
    }
    gostcrypt(&(c->cctx), iv, buf);
    c->count = c->count % 1024 + 8;
}

static void gost_cnt_next(void *ctx, unsigned char *iv, unsigned char *buf)
{
    struct ossl_gost_cipher_ctx *c = ctx;
    word32 g, go;
    unsigned char buf1[8];
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), iv);
    }
    if (c->count == 0) {
        gostcrypt(&(c->cctx), iv, buf1);
    } else {
        memcpy(buf1, iv, 8);
    }
    g = buf1[0] | (buf1[1] << 8) | (buf1[2] << 16) | ((word32) buf1[3] << 24);
    g += 0x01010101;
    buf1[0] = (unsigned char)(g & 0xff);
    buf1[1] = (unsigned char)((g >> 8) & 0xff);
    buf1[2] = (unsigned char)((g >> 16) & 0xff);
    buf1[3] = (unsigned char)((g >> 24) & 0xff);
    g = buf1[4] | (buf1[5] << 8) | (buf1[6] << 16) | ((word32) buf1[7] << 24);
    go = g;
    g += 0x01010104;
    if (go > g)                 /* overflow */
        g++;
    buf1[4] = (unsigned char)(g & 0xff);
    buf1[5] = (unsigned char)((g >> 8) & 0xff);
    buf1[6] = (unsigned char)((g >> 16) & 0xff);
    buf1[7] = (unsigned char)((g >> 24) & 0xff);
    memcpy(iv, buf1, 8);
    gostcrypt(&(c->cctx), buf1, buf);
    c->count = c->count % 1024 + 8;
}

/* GOST encryption in CFB mode */
int gost_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    size_t i = 0;
    size_t j = 0;
/* process partial block if any */
    if (EVP_CIPHER_CTX_num(ctx)) {
        for (j = EVP_CIPHER_CTX_num(ctx), i = 0; j < 8 && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            if (!EVP_CIPHER_CTX_encrypting(ctx))
                buf[j + 8] = *in_ptr;
            *out_ptr = buf[j] ^ (*in_ptr);
            if (EVP_CIPHER_CTX_encrypting(ctx))
                buf[j + 8] = *out_ptr;
        }
        if (j == 8) {
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), buf + 8, 8);
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, j);
            return 1;
        }
    }

    for (; i + 8 < inl; i += 8, in_ptr += 8, out_ptr += 8) {
        /*
         * block cipher current iv
         */
        gost_crypt_mesh(EVP_CIPHER_CTX_cipher_data(ctx),
                        EVP_CIPHER_CTX_iv_noconst(ctx), buf);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        if (!EVP_CIPHER_CTX_encrypting(ctx))
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), in_ptr, 8);
        for (j = 0; j < 8; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        /* Encrypt */
        /* Next iv is next block of cipher text */
        if (EVP_CIPHER_CTX_encrypting(ctx))
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), out_ptr, 8);
    }
/* Process rest of buffer */
    if (i < inl) {
        gost_crypt_mesh(EVP_CIPHER_CTX_cipher_data(ctx),
                        EVP_CIPHER_CTX_iv_noconst(ctx), buf);
        if (!EVP_CIPHER_CTX_encrypting(ctx))
            memcpy(buf + 8, in_ptr, inl - i);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, j);
        if (EVP_CIPHER_CTX_encrypting(ctx))
            memcpy(buf + 8, out_ptr, j);
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }
    return 1;
}

static int gost_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t inl)
{
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    size_t i = 0;
    size_t j;
/* process partial block if any */
    if (EVP_CIPHER_CTX_num(ctx)) {
        for (j = EVP_CIPHER_CTX_num(ctx), i = 0; j < 8 && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            *out_ptr = buf[j] ^ (*in_ptr);
        }
        if (j == 8) {
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, j);
            return 1;
        }
    }

    for (; i + 8 < inl; i += 8, in_ptr += 8, out_ptr += 8) {
        /*
         * block cipher current iv
         */
        /* Encrypt */
        gost_cnt_next(EVP_CIPHER_CTX_cipher_data(ctx),
                      EVP_CIPHER_CTX_iv_noconst(ctx), buf);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        for (j = 0; j < 8; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
    }
/* Process rest of buffer */
    if (i < inl) {
        gost_cnt_next(EVP_CIPHER_CTX_cipher_data(ctx),
                      EVP_CIPHER_CTX_iv_noconst(ctx), buf);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, j);
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }
    return 1;
}

/* Cleaning up of EVP_CIPHER_CTX */
int gost_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    gost_destroy(&((struct ossl_gost_cipher_ctx *)
                   EVP_CIPHER_CTX_cipher_data(ctx))->cctx);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);
    return 1;
}

/* Control function for gost cipher */
int gost_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_CTRL_RAND_KEY:
        {
            if (RAND_bytes((unsigned char *)ptr,
                           EVP_CIPHER_CTX_key_length(ctx)) <= 0) {
                GOSTerr(GOST_F_GOST_CIPHER_CTL,
                        GOST_R_RANDOM_GENERATOR_ERROR);
                return -1;
            }
            break;
        }
    case EVP_CTRL_PBE_PRF_NID:
        if (ptr) {
            *((int *)ptr) = NID_id_HMACGostR3411_94;
            return 1;
        } else {
            return 0;
        }

    default:
        GOSTerr(GOST_F_GOST_CIPHER_CTL,
                GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
        return -1;
    }
    return 1;
}

/* Set cipher parameters from ASN1 structure */
int gost89_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *p = NULL;
    struct ossl_gost_cipher_ctx *c = EVP_CIPHER_CTX_cipher_data(ctx);
    GOST_CIPHER_PARAMS *gcp = GOST_CIPHER_PARAMS_new();
    ASN1_OCTET_STRING *os = NULL;
    if (!gcp) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!ASN1_OCTET_STRING_set(gcp->iv, EVP_CIPHER_CTX_iv(ctx),
                               EVP_CIPHER_CTX_iv_length(ctx))) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ASN1_OBJECT_free(gcp->enc_param_set);
    gcp->enc_param_set = OBJ_nid2obj(c->paramNID);

    len = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    p = buf = OPENSSL_malloc(len);
    if (!buf) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    i2d_GOST_CIPHER_PARAMS(gcp, &p);
    GOST_CIPHER_PARAMS_free(gcp);

    os = ASN1_OCTET_STRING_new();

    if (!os || !ASN1_OCTET_STRING_set(os, buf, len)) {
        OPENSSL_free(buf);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OPENSSL_free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    return 1;
}

/* Store parameters into ASN1 structure */
int gost89_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int ret = -1;
    int len;
    GOST_CIPHER_PARAMS *gcp = NULL;
    unsigned char *p;
    struct ossl_gost_cipher_ctx *c = EVP_CIPHER_CTX_cipher_data(ctx);
    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        return ret;
    }

    p = params->value.sequence->data;

    gcp = d2i_GOST_CIPHER_PARAMS(NULL, (const unsigned char **)&p,
                                 params->value.sequence->length);

    len = gcp->iv->length;
    if (len != EVP_CIPHER_CTX_iv_length(ctx)) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_GET_ASN1_PARAMETERS, GOST_R_INVALID_IV_LENGTH);
        return -1;
    }
    if (!gost_cipher_set_param(c, OBJ_obj2nid(gcp->enc_param_set))) {
        GOST_CIPHER_PARAMS_free(gcp);
        return -1;
    }
    memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), gcp->iv->data,
           EVP_CIPHER_CTX_iv_length(ctx));

    GOST_CIPHER_PARAMS_free(gcp);

    return 1;
}

int gost_imit_init_cpa(EVP_MD_CTX *ctx)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    memset(c->buffer, 0, sizeof(c->buffer));
    memset(c->partial_block, 0, sizeof(c->partial_block));
    c->count = 0;
    c->bytes_left = 0;
    c->key_meshing = 1;
    gost_init(&(c->cctx), &Gost28147_CryptoProParamSetA);
    return 1;
}

static void mac_block_mesh(struct ossl_gost_imit_ctx *c,
                           const unsigned char *data)
{
    unsigned char buffer[8];
    /*
     * We are using local buffer for iv because CryptoPro doesn't interpret
     * internal state of MAC algorithm as iv during keymeshing (but does
     * initialize internal state from iv in key transport
     */
    assert(c->count % 8 == 0 && c->count <= 1024);
    if (c->key_meshing && c->count == 1024) {
        cryptopro_key_meshing(&(c->cctx), buffer);
    }
    mac_block(&(c->cctx), c->buffer, data);
    c->count = c->count % 1024 + 8;
}

int gost_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    const unsigned char *p = data;
    size_t bytes = count, i;
    if (!(c->key_set)) {
        GOSTerr(GOST_F_GOST_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->bytes_left) {
        for (i = c->bytes_left; i < 8 && bytes > 0; bytes--, i++, p++) {
            c->partial_block[i] = *p;
        }
        if (i == 8) {
            mac_block_mesh(c, c->partial_block);
        } else {
            c->bytes_left = i;
            return 1;
        }
    }
    while (bytes > 8) {
        mac_block_mesh(c, p);
        p += 8;
        bytes -= 8;
    }
    if (bytes > 0) {
        memcpy(c->partial_block, p, bytes);
    }
    c->bytes_left = bytes;
    return 1;
}

int gost_imit_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct ossl_gost_imit_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (!c->key_set) {
        GOSTerr(GOST_F_GOST_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }
    if (c->count == 0 && c->bytes_left) {
        unsigned char buffer[8];
        memset(buffer, 0, 8);
        gost_imit_update(ctx, buffer, 8);
    }
    if (c->bytes_left) {
        int i;
        for (i = c->bytes_left; i < 8; i++) {
            c->partial_block[i] = 0;
        }
        mac_block_mesh(c, c->partial_block);
    }
    get_mac(c->buffer, 32, md);
    return 1;
}

int gost_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            if (arg != 32) {
                GOSTerr(GOST_F_GOST_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_LENGTH);
                return 0;
            }

            gost_key(&(((struct ossl_gost_imit_ctx *)(EVP_MD_CTX_md_data(ctx)))->cctx),
                     ptr);
            ((struct ossl_gost_imit_ctx *)(EVP_MD_CTX_md_data(ctx)))->key_set = 1;
            return 1;

        }
    default:
        return 0;
    }
}

int gost_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    memcpy(EVP_MD_CTX_md_data(to), EVP_MD_CTX_md_data(from),
           sizeof(struct ossl_gost_imit_ctx));
    return 1;
}

/* Clean up imit ctx */
int gost_imit_cleanup(EVP_MD_CTX *ctx)
{
    memset(EVP_MD_CTX_md_data(ctx), 0, sizeof(struct ossl_gost_imit_ctx));
    return 1;
}
