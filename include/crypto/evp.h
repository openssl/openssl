/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_numbers.h>
#include "internal/refcount.h"

/*
 * Don't free up md_ctx->pctx in EVP_MD_CTX_reset, use the reserved flag
 * values in evp.h
 */
#define EVP_MD_CTX_FLAG_KEEP_PKEY_CTX   0x0400

struct evp_pkey_ctx_st {
    /* Actual operation */
    int operation;

    /*
     * Library context, Algorithm name and properties associated
     * with this context
     */
    OPENSSL_CTX *libctx;
    const char *algorithm;
    const char *propquery;

    /* cached key manager */
    EVP_KEYMGMT *keymgmt;

    union {
        struct {
            EVP_KEYEXCH *exchange;
            void *exchprovctx;
        } kex;

        struct {
            EVP_SIGNATURE *signature;
            void *sigprovctx;
        } sig;
    } op;

    /* Legacy fields below */

    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */ ;

#define EVP_PKEY_FLAG_DYNAMIC   1

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVP_PKEY_CTX *ctx);
    int (*copy) (EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src);
    void (*cleanup) (EVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVP_PKEY_CTX *ctx);
    int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init) (EVP_PKEY_CTX *ctx);
    int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);
    int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVP_PKEY_CTX *ctx);
    int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
    int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen);
    int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen);
    int (*check) (EVP_PKEY *pkey);
    int (*public_check) (EVP_PKEY *pkey);
    int (*param_check) (EVP_PKEY *pkey);

    int (*digest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
} /* EVP_PKEY_METHOD */ ;

DEFINE_STACK_OF_CONST(EVP_PKEY_METHOD)

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx);

const EVP_PKEY_METHOD *cmac_pkey_method(void);
const EVP_PKEY_METHOD *dh_pkey_method(void);
const EVP_PKEY_METHOD *dhx_pkey_method(void);
const EVP_PKEY_METHOD *dsa_pkey_method(void);
const EVP_PKEY_METHOD *ec_pkey_method(void);
const EVP_PKEY_METHOD *sm2_pkey_method(void);
const EVP_PKEY_METHOD *ecx25519_pkey_method(void);
const EVP_PKEY_METHOD *ecx448_pkey_method(void);
const EVP_PKEY_METHOD *ed25519_pkey_method(void);
const EVP_PKEY_METHOD *ed448_pkey_method(void);
const EVP_PKEY_METHOD *hmac_pkey_method(void);
const EVP_PKEY_METHOD *rsa_pkey_method(void);
const EVP_PKEY_METHOD *rsa_pss_pkey_method(void);
const EVP_PKEY_METHOD *scrypt_pkey_method(void);
const EVP_PKEY_METHOD *tls1_prf_pkey_method(void);
const EVP_PKEY_METHOD *hkdf_pkey_method(void);
const EVP_PKEY_METHOD *poly1305_pkey_method(void);
const EVP_PKEY_METHOD *siphash_pkey_method(void);

struct evp_mac_st {
    OSSL_PROVIDER *prov;
    int name_id;

    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    OSSL_OP_mac_newctx_fn *newctx;
    OSSL_OP_mac_dupctx_fn *dupctx;
    OSSL_OP_mac_freectx_fn *freectx;
    OSSL_OP_mac_size_fn *size;
    OSSL_OP_mac_init_fn *init;
    OSSL_OP_mac_update_fn *update;
    OSSL_OP_mac_final_fn *final;
    OSSL_OP_mac_gettable_params_fn *gettable_params;
    OSSL_OP_mac_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_OP_mac_settable_ctx_params_fn *settable_ctx_params;
    OSSL_OP_mac_get_params_fn *get_params;
    OSSL_OP_mac_get_ctx_params_fn *get_ctx_params;
    OSSL_OP_mac_set_ctx_params_fn *set_ctx_params;
};

struct evp_kdf_st {
    OSSL_PROVIDER *prov;
    int name_id;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    OSSL_OP_kdf_newctx_fn *newctx;
    OSSL_OP_kdf_dupctx_fn *dupctx;
    OSSL_OP_kdf_freectx_fn *freectx;
    OSSL_OP_kdf_reset_fn *reset;
    OSSL_OP_kdf_derive_fn *derive;
    OSSL_OP_kdf_gettable_params_fn *gettable_params;
    OSSL_OP_kdf_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_OP_kdf_settable_ctx_params_fn *settable_ctx_params;
    OSSL_OP_kdf_get_params_fn *get_params;
    OSSL_OP_kdf_get_ctx_params_fn *get_ctx_params;
    OSSL_OP_kdf_set_ctx_params_fn *set_ctx_params;
};

struct evp_md_st {
    /* nid */
    int type;

    /* Legacy structure members */
    /* TODO(3.0): Remove these */
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);

    /* New structure members */
    /* TODO(3.0): Remove above comment when legacy has gone */
    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
    OSSL_OP_digest_newctx_fn *newctx;
    OSSL_OP_digest_init_fn *dinit;
    OSSL_OP_digest_update_fn *dupdate;
    OSSL_OP_digest_final_fn *dfinal;
    OSSL_OP_digest_digest_fn *digest;
    OSSL_OP_digest_freectx_fn *freectx;
    OSSL_OP_digest_dupctx_fn *dupctx;
    OSSL_OP_digest_get_params_fn *get_params;
    OSSL_OP_digest_set_ctx_params_fn *set_ctx_params;
    OSSL_OP_digest_get_ctx_params_fn *get_ctx_params;
    OSSL_OP_digest_gettable_params_fn *gettable_params;
    OSSL_OP_digest_settable_ctx_params_fn *settable_ctx_params;
    OSSL_OP_digest_gettable_ctx_params_fn *gettable_ctx_params;

} /* EVP_MD */ ;

struct evp_cipher_st {
    int nid;

    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;

    /* Legacy structure members */
    /* TODO(3.0): Remove these */
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;

    /* New structure members */
    /* TODO(3.0): Remove above comment when legacy has gone */
    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
    OSSL_OP_cipher_newctx_fn *newctx;
    OSSL_OP_cipher_encrypt_init_fn *einit;
    OSSL_OP_cipher_decrypt_init_fn *dinit;
    OSSL_OP_cipher_update_fn *cupdate;
    OSSL_OP_cipher_final_fn *cfinal;
    OSSL_OP_cipher_cipher_fn *ccipher;
    OSSL_OP_cipher_freectx_fn *freectx;
    OSSL_OP_cipher_dupctx_fn *dupctx;
    OSSL_OP_cipher_get_params_fn *get_params;
    OSSL_OP_cipher_get_ctx_params_fn *get_ctx_params;
    OSSL_OP_cipher_set_ctx_params_fn *set_ctx_params;
    OSSL_OP_cipher_gettable_params_fn *gettable_params;
    OSSL_OP_cipher_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_OP_cipher_settable_ctx_params_fn *settable_ctx_params;
} /* EVP_CIPHER */ ;

/* Macros to code block cipher wrappers */

/* Wrapper functions for each cipher mode */

#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))

#define BLOCK_CIPHER_ecb_loop() \
        size_t i, bl; \
        bl = EVP_CIPHER_CTX_cipher(ctx)->block_size;    \
        if (inl < bl) return 1;\
        inl -= bl; \
        for (i=0; i <= inl; i+=bl)

#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
static int cname##_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        BLOCK_CIPHER_ecb_loop() \
            cprefix##_ecb_encrypt(in + i, out + i, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_encrypting(ctx)); \
        return 1;\
}

#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
    static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
        }\
        if (inl) {\
            int num = EVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVP_CIPHER_CTX_set_num(ctx, num);\
        }\
        return 1;\
}

#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVP_MAXCHUNK) \
            {\
            cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
            inl-=EVP_MAXCHUNK;\
            in +=EVP_MAXCHUNK;\
            out+=EVP_MAXCHUNK;\
            }\
        if (inl)\
            cprefix##_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(kstruct,ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx));\
        return 1;\
}

#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)  \
static int cname##_cfb##cbits##_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
    size_t chunk = EVP_MAXCHUNK;\
    if (cbits == 1)  chunk >>= 3;\
    if (inl < chunk) chunk = inl;\
    while (inl && inl >= chunk)\
    {\
        int num = EVP_CIPHER_CTX_num(ctx);\
        cprefix##_cfb##cbits##_encrypt(in, out, (long) \
            ((cbits == 1) \
                && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) \
                ? chunk*8 : chunk), \
            &EVP_C_DATA(kstruct, ctx)->ksched, EVP_CIPHER_CTX_iv_noconst(ctx),\
            &num, EVP_CIPHER_CTX_encrypting(ctx));\
        EVP_CIPHER_CTX_set_num(ctx, num);\
        inl -= chunk;\
        in += chunk;\
        out += chunk;\
        if (inl < chunk) chunk = inl;\
    }\
    return 1;\
}

#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)

#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size, \
                          key_len, iv_len, flags, init_key, cleanup, \
                          set_asn1, get_asn1, ctrl) \
static const EVP_CIPHER cname##_##mode = { \
        nid##_##nmode, block_size, key_len, iv_len, \
        flags | EVP_CIPH_##MODE##_MODE, \
        init_key, \
        cname##_##mode##_cipher, \
        cleanup, \
        sizeof(kstruct), \
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
}; \
const EVP_CIPHER *EVP_##cname##_##mode(void) { return &cname##_##mode; }

#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, \
                             iv_len, flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
                  iv_len, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
                             flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
                  0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_defs(cname, kstruct, \
                          nid, block_size, key_len, iv_len, cbits, flags, \
                          init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl)

/*-
#define BLOCK_CIPHER_defs(cname, kstruct, \
                                nid, block_size, key_len, iv_len, flags,\
                                 init_key, cleanup, set_asn1, get_asn1, ctrl)\
static const EVP_CIPHER cname##_cbc = {\
        nid##_cbc, block_size, key_len, iv_len, \
        flags | EVP_CIPH_CBC_MODE,\
        init_key,\
        cname##_cbc_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_cbc(void) { return &cname##_cbc; }\
static const EVP_CIPHER cname##_cfb = {\
        nid##_cfb64, 1, key_len, iv_len, \
        flags | EVP_CIPH_CFB_MODE,\
        init_key,\
        cname##_cfb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_cfb(void) { return &cname##_cfb; }\
static const EVP_CIPHER cname##_ofb = {\
        nid##_ofb64, 1, key_len, iv_len, \
        flags | EVP_CIPH_OFB_MODE,\
        init_key,\
        cname##_ofb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_ofb(void) { return &cname##_ofb; }\
static const EVP_CIPHER cname##_ecb = {\
        nid##_ecb, block_size, key_len, iv_len, \
        flags | EVP_CIPH_ECB_MODE,\
        init_key,\
        cname##_ecb_cipher,\
        cleanup,\
        sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVP_CIPHER *EVP_##cname##_ecb(void) { return &cname##_ecb; }
*/

#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid, \
                               block_size, key_len, iv_len, cbits, \
                               flags, init_key, \
                               cleanup, set_asn1, get_asn1, ctrl) \
        BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len, \
                          cbits, flags, init_key, cleanup, set_asn1, \
                          get_asn1, ctrl)

#define IMPLEMENT_CFBR(cipher,cprefix,kstruct,ksched,keysize,cbits,iv_len,fl) \
        BLOCK_CIPHER_func_cfb(cipher##_##keysize,cprefix,cbits,kstruct,ksched) \
        BLOCK_CIPHER_def_cfb(cipher##_##keysize,kstruct, \
                             NID_##cipher##_##keysize, keysize/8, iv_len, cbits, \
                             (fl)|EVP_CIPH_FLAG_DEFAULT_ASN1, \
                             cipher##_init_key, NULL, NULL, NULL, NULL)


# ifndef OPENSSL_NO_EC

#define X25519_KEYLEN        32
#define X448_KEYLEN          56
#define ED25519_KEYLEN       32
#define ED448_KEYLEN         57

#define MAX_KEYLEN  ED448_KEYLEN

typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;

#endif

/*
 * Type needs to be a bit field Sub-type needs to be for variations on the
 * method, as in, can it do arbitrary encryption....
 */
struct evp_pkey_st {
    /* == Legacy attributes == */
    int type;
    int save_type;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;

    /* == Common attributes == */
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    int save_parameters;

    /* == Provider attributes == */
    /*
     * To support transparent export/import between providers that
     * support the methods for it, and still not having to do the
     * export/import every time a key or domain params are used, we
     * maintain a cache of imported key / domain params, indexed by
     * provider address.  pkeys[0] is *always* the "original" data.
     */
    struct {
        EVP_KEYMGMT *keymgmt;
        void *provdata;
        /* 0 = provdata is a key, 1 = provdata is domain params */
        int domainparams;
    } pkeys[10];
    /*
     * If there is a legacy key assigned to this structure, we keep
     * a copy of that key's dirty count.
     */
    size_t dirty_cnt_copy;
} /* EVP_PKEY */ ;

#define EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_SIGN \
     || (ctx)->operation == EVP_PKEY_OP_SIGNCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFY \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYRECOVER)

#define EVP_PKEY_CTX_IS_DERIVE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_DERIVE)

void openssl_add_all_ciphers_int(void);
void openssl_add_all_digests_int(void);
void evp_cleanup_int(void);
void evp_app_cleanup_int(void);

/* KEYMGMT helper functions */
void *evp_keymgmt_export_to_provider(EVP_PKEY *pk, EVP_KEYMGMT *keymgmt,
                                     int domainparams);
void evp_keymgmt_clear_pkey_cache(EVP_PKEY *pk);
void *evp_keymgmt_fromdata(EVP_PKEY *target, EVP_KEYMGMT *keymgmt,
                           const OSSL_PARAM params[], int domainparams);


/* KEYMGMT provider interface functions */
void *evp_keymgmt_importdomparams(const EVP_KEYMGMT *keymgmt,
                                  const OSSL_PARAM params[]);
void *evp_keymgmt_gendomparams(const EVP_KEYMGMT *keymgmt,
                            const OSSL_PARAM params[]);
void evp_keymgmt_freedomparams(const EVP_KEYMGMT *keymgmt,
                               void *provdomparams);
int evp_keymgmt_exportdomparams(const EVP_KEYMGMT *keymgmt,
                                void *provdomparams, OSSL_PARAM params[]);
const OSSL_PARAM *
evp_keymgmt_importdomparam_types(const EVP_KEYMGMT *keymgmt);
const OSSL_PARAM *
evp_keymgmt_exportdomparam_types(const EVP_KEYMGMT *keymgmt);

void *evp_keymgmt_importkey(const EVP_KEYMGMT *keymgmt,
                            const OSSL_PARAM params[]);
void *evp_keymgmt_genkey(const EVP_KEYMGMT *keymgmt, void *domparams,
                         const OSSL_PARAM params[]);
void *evp_keymgmt_loadkey(const EVP_KEYMGMT *keymgmt,
                          void *id, size_t idlen);
void evp_keymgmt_freekey(const EVP_KEYMGMT *keymgmt, void *provkey);
int evp_keymgmt_exportkey(const EVP_KEYMGMT *keymgmt,
                               void *provkey, OSSL_PARAM params[]);
const OSSL_PARAM *evp_keymgmt_importkey_types(const EVP_KEYMGMT *keymgmt);
const OSSL_PARAM *evp_keymgmt_exportkey_types(const EVP_KEYMGMT *keymgmt);

/* Pulling defines out of C source files */

#define EVP_RC4_KEY_SIZE 16
#ifndef TLS1_1_VERSION
# define TLS1_1_VERSION   0x0302
#endif

void evp_encode_ctx_set_flags(EVP_ENCODE_CTX *ctx, unsigned int flags);

/* EVP_ENCODE_CTX flags */
/* Don't generate new lines when encoding */
#define EVP_ENCODE_CTX_NO_NEWLINES          1
/* Use the SRP base64 alphabet instead of the standard one */
#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2

const EVP_CIPHER *evp_get_cipherbyname_ex(OPENSSL_CTX *libctx, const char *name);
const EVP_MD *evp_get_digestbyname_ex(OPENSSL_CTX *libctx, const char *name);
