/*
 * Copyright 2000-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* EVP_MD_CTX related stuff */

#include <openssl/core_numbers.h>

struct evp_md_ctx_st {
    const EVP_MD *reqdigest;    /* The original requested digest */
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);

    /* Provider ctx */
    void *provctx;
    EVP_MD *fetched_digest;
} /* EVP_MD_CTX */ ;

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */

    /* Provider ctx */
    void *provctx;
    EVP_CIPHER *fetched_cipher;
} /* EVP_CIPHER_CTX */ ;

struct evp_mac_ctx_st {
    const EVP_MAC *meth;         /* Method structure */
    void *data;                  /* Individual method data */
} /* EVP_MAC_CTX */;

struct evp_kdf_ctx_st {
    const EVP_KDF *meth;         /* Method structure */
    EVP_KDF_IMPL *impl;          /* Algorithm-specific data */
} /* EVP_KDF_CTX */ ;

struct evp_keymgmt_st {
    int id;                      /* libcrypto internal */

    const char *name;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    /* Domain parameter routines */
    OSSL_OP_keymgmt_importdomain_fn *importdomain;
    OSSL_OP_keymgmt_gendomain_fn *gendomain;
    OSSL_OP_keymgmt_freedomain_fn *freedomain;
    OSSL_OP_keymgmt_exportdomain_fn *exportdomain;
    OSSL_OP_keymgmt_importdomain_types_fn *importdomain_types;
    OSSL_OP_keymgmt_exportdomain_types_fn *exportdomain_types;

    /* Key routines */
    OSSL_OP_keymgmt_importkey_priv_fn *importkey_priv;
    OSSL_OP_keymgmt_importkey_pub_fn *importkey_pub;
    OSSL_OP_keymgmt_genkey_fn *genkey;
    OSSL_OP_keymgmt_loadkey_fn *loadkey;
    OSSL_OP_keymgmt_freekey_fn *freekey;
    OSSL_OP_keymgmt_exportkey_priv_fn *exportkey_priv;
    OSSL_OP_keymgmt_exportkey_pub_fn *exportkey_pub;
    OSSL_OP_keymgmt_importkey_priv_types_fn *importkey_priv_types;
    OSSL_OP_keymgmt_importkey_pub_types_fn *importkey_pub_types;
    OSSL_OP_keymgmt_exportkey_priv_types_fn *exportkey_priv_types;
    OSSL_OP_keymgmt_exportkey_pub_types_fn *exportkey_pub_types;
} /* EVP_KEYMGMT */ ;

struct evp_keyexch_st {
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    OSSL_OP_keyexch_newctx_fn *newctx;
    OSSL_OP_keyexch_init_fn *init;
    OSSL_OP_keyexch_set_peer_fn *set_peer;
    OSSL_OP_keyexch_derive_fn *derive;
    OSSL_OP_keyexch_freectx_fn *freectx;
    OSSL_OP_keyexch_dupctx_fn *dupctx;
    OSSL_OP_keyexch_set_params_fn *set_params;
} /* EVP_KEYEXCH */;

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md,
                             int en_de);

struct evp_Encode_Ctx_st {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    unsigned int flags;
};

typedef struct evp_pbe_st EVP_PBE_CTL;
DEFINE_STACK_OF(EVP_PBE_CTL)

int is_partially_overlapping(const void *ptr1, const void *ptr2, int len);

#include <openssl/ossl_typ.h>
#include <openssl/core.h>

void *evp_generic_fetch(OPENSSL_CTX *ctx, int operation_id,
                        const char *algorithm, const char *properties,
                        void *(*new_method)(const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov),
                        int (*up_ref_method)(void *),
                        void (*free_method)(void *));

/* Helper functions to avoid duplicating code */

/*
 * These methods implement different ways to pass a params array to the
 * provider.  They will return one of these values:
 *
 * -2 if the method doesn't come from a provider
 *    (evp_do_param will return this to the called)
 * -1 if the provider doesn't offer the desired function
 *    (evp_do_param will raise an error and return 0)
 * or the return value from the desired function
 *    (evp_do_param will return it to the caller)
 */
int evp_do_ciph_getparams(const EVP_CIPHER *ciph, OSSL_PARAM params[]);
int evp_do_ciph_ctx_getparams(const EVP_CIPHER *ciph, void *provctx,
                              OSSL_PARAM params[]);
int evp_do_ciph_ctx_setparams(const EVP_CIPHER *ciph, void *provctx,
                              OSSL_PARAM params[]);

OSSL_PARAM *evp_pkey_to_param(EVP_PKEY *pkey, size_t *sz);

#define M_check_autoarg(ctx, arg, arglen, err) \
    if (ctx->pmeth->flags & EVP_PKEY_FLAG_AUTOARGLEN) {           \
        size_t pksize = (size_t)EVP_PKEY_size(ctx->pkey);         \
                                                                  \
        if (pksize == 0) {                                        \
            EVPerr(err, EVP_R_INVALID_KEY); /*ckerr_ignore*/      \
            return 0;                                             \
        }                                                         \
        if (arg == NULL) {                                        \
            *arglen = pksize;                                     \
            return 1;                                             \
        }                                                         \
        if (*arglen < pksize) {                                   \
            EVPerr(err, EVP_R_BUFFER_TOO_SMALL); /*ckerr_ignore*/ \
            return 0;                                             \
        }                                                         \
    }
