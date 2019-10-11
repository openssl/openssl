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

#define EVP_CTRL_RET_UNSUPPORTED -1


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
    EVP_MAC *meth;               /* Method structure */
    void *data;                  /* Individual method data */
} /* EVP_MAC_CTX */;

struct evp_kdf_ctx_st {
    EVP_KDF *meth;              /* Method structure */
    void *data;                 /* Algorithm-specific data */
} /* EVP_KDF_CTX */ ;

struct evp_keymgmt_st {
    int id;                      /* libcrypto internal */

    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    /* Domain parameter routines */
    OSSL_OP_keymgmt_importdomparams_fn *importdomparams;
    OSSL_OP_keymgmt_gendomparams_fn *gendomparams;
    OSSL_OP_keymgmt_freedomparams_fn *freedomparams;
    OSSL_OP_keymgmt_exportdomparams_fn *exportdomparams;
    OSSL_OP_keymgmt_importdomparam_types_fn *importdomparam_types;
    OSSL_OP_keymgmt_exportdomparam_types_fn *exportdomparam_types;

    /* Key routines */
    OSSL_OP_keymgmt_importkey_fn *importkey;
    OSSL_OP_keymgmt_genkey_fn *genkey;
    OSSL_OP_keymgmt_loadkey_fn *loadkey;
    OSSL_OP_keymgmt_freekey_fn *freekey;
    OSSL_OP_keymgmt_exportkey_fn *exportkey;
    OSSL_OP_keymgmt_importkey_types_fn *importkey_types;
    OSSL_OP_keymgmt_exportkey_types_fn *exportkey_types;
} /* EVP_KEYMGMT */ ;

struct keymgmt_data_st {
    OPENSSL_CTX *ctx;
    const char *properties;
};

struct evp_keyexch_st {
    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    EVP_KEYMGMT *keymgmt;

    OSSL_OP_keyexch_newctx_fn *newctx;
    OSSL_OP_keyexch_init_fn *init;
    OSSL_OP_keyexch_set_peer_fn *set_peer;
    OSSL_OP_keyexch_derive_fn *derive;
    OSSL_OP_keyexch_freectx_fn *freectx;
    OSSL_OP_keyexch_dupctx_fn *dupctx;
    OSSL_OP_keyexch_set_ctx_params_fn *set_ctx_params;
    OSSL_OP_keyexch_settable_ctx_params_fn *settable_ctx_params;
} /* EVP_KEYEXCH */;

struct evp_signature_st {
    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    EVP_KEYMGMT *keymgmt;

    OSSL_OP_signature_newctx_fn *newctx;
    OSSL_OP_signature_sign_init_fn *sign_init;
    OSSL_OP_signature_sign_fn *sign;
    OSSL_OP_signature_verify_init_fn *verify_init;
    OSSL_OP_signature_verify_fn *verify;
    OSSL_OP_signature_verify_recover_init_fn *verify_recover_init;
    OSSL_OP_signature_verify_recover_fn *verify_recover;
    OSSL_OP_signature_digest_sign_init_fn *digest_sign_init;
    OSSL_OP_signature_digest_sign_update_fn *digest_sign_update;
    OSSL_OP_signature_digest_sign_final_fn *digest_sign_final;
    OSSL_OP_signature_digest_verify_init_fn *digest_verify_init;
    OSSL_OP_signature_digest_verify_update_fn *digest_verify_update;
    OSSL_OP_signature_digest_verify_final_fn *digest_verify_final;
    OSSL_OP_signature_freectx_fn *freectx;
    OSSL_OP_signature_dupctx_fn *dupctx;
    OSSL_OP_signature_get_ctx_params_fn *get_ctx_params;
    OSSL_OP_signature_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_OP_signature_set_ctx_params_fn *set_ctx_params;
    OSSL_OP_signature_settable_ctx_params_fn *settable_ctx_params;
    OSSL_OP_signature_get_ctx_md_params_fn *get_ctx_md_params;
    OSSL_OP_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params;
    OSSL_OP_signature_set_ctx_md_params_fn *set_ctx_md_params;
    OSSL_OP_signature_settable_ctx_md_params_fn *settable_ctx_md_params;
} /* EVP_SIGNATURE */;

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

#include <openssl/types.h>
#include <openssl/core.h>

void *evp_generic_fetch(OPENSSL_CTX *ctx, int operation_id,
                        const char *name, const char *properties,
                        void *(*new_method)(int name_id,
                                            const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov,
                                            void *method_data),
                        void *method_data,
                        int (*up_ref_method)(void *),
                        void (*free_method)(void *));
void *evp_generic_fetch_by_number(OPENSSL_CTX *ctx, int operation_id,
                                  int name_id, const char *properties,
                                  void *(*new_method)(int name_id,
                                                      const OSSL_DISPATCH *fns,
                                                      OSSL_PROVIDER *prov,
                                                      void *method_data),
                                  void *method_data,
                                  int (*up_ref_method)(void *),
                                  void (*free_method)(void *));
void evp_generic_do_all(OPENSSL_CTX *libctx, int operation_id,
                        void (*user_fn)(void *method, void *arg),
                        void *user_arg,
                        void *(*new_method)(int name_id,
                                            const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov,
                                            void *method_data),
                        void *method_data,
                        void (*free_method)(void *));

/* Internal fetchers for method types that are to be combined with others */
EVP_KEYMGMT *evp_keymgmt_fetch_by_number(OPENSSL_CTX *ctx, int name_id,
                                         const char *properties);

/* Internal structure constructors for fetched methods */
EVP_MD *evp_md_new(void);
EVP_CIPHER *evp_cipher_new(void);

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
int evp_do_md_getparams(const EVP_MD *md, OSSL_PARAM params[]);
int evp_do_md_ctx_getparams(const EVP_MD *md, void *provctx,
                            OSSL_PARAM params[]);
int evp_do_md_ctx_setparams(const EVP_MD *md, void *provctx,
                            OSSL_PARAM params[]);

OSSL_PARAM *evp_pkey_to_param(EVP_PKEY *pkey, size_t *sz);

#define M_check_autoarg(ctx, arg, arglen, err) \
    if (ctx->pmeth->flags & EVP_PKEY_FLAG_AUTOARGLEN) {           \
        size_t pksize = (size_t)EVP_PKEY_size(ctx->pkey);         \
                                                                  \
        if (pksize == 0) {                                        \
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY); /*ckerr_ignore*/ \
            return 0;                                             \
        }                                                         \
        if (arg == NULL) {                                        \
            *arglen = pksize;                                     \
            return 1;                                             \
        }                                                         \
        if (*arglen < pksize) {                                   \
            ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL); /*ckerr_ignore*/ \
            return 0;                                             \
        }                                                         \
    }

void evp_pkey_ctx_free_old_ops(EVP_PKEY_CTX *ctx);

/* OSSL_PROVIDER * is only used to get the library context */
const char *evp_first_name(OSSL_PROVIDER *prov, int name_id);
int evp_is_a(OSSL_PROVIDER *prov, int number, const char *name);
void evp_doall_names(OSSL_PROVIDER *prov, int number,
                     void (*fn)(const char *name, void *data),
                     void *data);
