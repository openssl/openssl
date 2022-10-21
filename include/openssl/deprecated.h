/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EVP_DEPRECATED_H
# define OPENSSL_EVP_DEPRECATED_H
# pragma once

# include <stddef.h>  /* size_t */
# include <openssl/types.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Deprecated Cipher methods */

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
#  define EVP_CIPHER_CTX_init(c)      EVP_CIPHER_CTX_reset(c)
#  define EVP_CIPHER_CTX_cleanup(c)   EVP_CIPHER_CTX_reset(c)
#  define EVP_CIPHER_CTX_flags(c)     EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c))
# endif /* OPENSSL_NO_DEPRECATED_1_1_0 */

# ifndef OPENSSL_NO_DEPRECATED_3_0

OSSL_DEPRECATEDIN_3_0 const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
OSSL_DEPRECATEDIN_3_0 int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);

OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
OSSL_DEPRECATEDIN_3_0
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);
OSSL_DEPRECATEDIN_3_0
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                             int (*init) (EVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc));
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                                  int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl));
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
                                int (*cleanup) (EVP_CIPHER_CTX *));
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
OSSL_DEPRECATEDIN_3_0
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
                             int (*ctrl) (EVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr));
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_init(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                      const unsigned char *key,
                                                      const unsigned char *iv,
                                                      int enc);
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                           unsigned char *out,
                                                           const unsigned char *in,
                                                           size_t inl);
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *);
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                                 ASN1_TYPE *);
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                                 ASN1_TYPE *);
OSSL_DEPRECATEDIN_3_0 int
(*EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *, int type,
                                                      int arg, void *ptr);

/* Deprecated Digest methods */

#  ifndef EVP_MD

OSSL_DEPRECATEDIN_3_0 const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count);
OSSL_DEPRECATEDIN_3_0
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (*update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count));

OSSL_DEPRECATEDIN_3_0 EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
OSSL_DEPRECATEDIN_3_0 EVP_MD *EVP_MD_meth_dup(const EVP_MD *md);
OSSL_DEPRECATEDIN_3_0 void EVP_MD_meth_free(EVP_MD *md);
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md));
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from));
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2));
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_input_blocksize(const EVP_MD *md);
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_result_size(const EVP_MD *md);
OSSL_DEPRECATEDIN_3_0 int EVP_MD_meth_get_app_datasize(const EVP_MD *md);
OSSL_DEPRECATEDIN_3_0 unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data, size_t count);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);
OSSL_DEPRECATEDIN_3_0
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2);
#  endif /* EVP_MD */

/* Deprecated PKEY methods */

#  define EVP_PK_RSA      0x0001
#  define EVP_PK_DSA      0x0002
#  define EVP_PK_DH       0x0004
#  define EVP_PK_EC       0x0008
#  define EVP_PKT_SIGN    0x0010
#  define EVP_PKT_ENC     0x0020
#  define EVP_PKT_EXCH    0x0040
#  define EVP_PKS_RSA     0x0100
#  define EVP_PKS_DSA     0x0200
#  define EVP_PKS_EC      0x0400

#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                                         (rsa))
#  ifndef OPENSSL_NO_EC
#   define EVP_PKEY_assign_EC_KEY(pkey,eckey) \
        EVP_PKEY_assign((pkey), EVP_PKEY_EC, (eckey))
#  endif

#  ifndef OPENSSL_NO_DSA
#   define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                                         (dsa))
#  endif

#  if !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#   define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,(dh))
#  endif

#  ifndef OPENSSL_NO_SIPHASH
#   define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),\
                                                 EVP_PKEY_SIPHASH,(shkey))
#  endif

# ifndef OPENSSL_NO_POLY1305
#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),\
                                                   EVP_PKEY_POLY1305,(polykey))
# endif


OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
                                             int (*init) (EVP_PKEY_CTX *ctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_copy
    (EVP_PKEY_METHOD *pmeth, int (*copy) (EVP_PKEY_CTX *dst,
                                          const EVP_PKEY_CTX *src));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_cleanup
    (EVP_PKEY_METHOD *pmeth, void (*cleanup) (EVP_PKEY_CTX *ctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_paramgen
    (EVP_PKEY_METHOD *pmeth, int (*paramgen_init) (EVP_PKEY_CTX *ctx),
     int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_keygen
    (EVP_PKEY_METHOD *pmeth, int (*keygen_init) (EVP_PKEY_CTX *ctx),
     int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_sign
    (EVP_PKEY_METHOD *pmeth, int (*sign_init) (EVP_PKEY_CTX *ctx),
     int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify
    (EVP_PKEY_METHOD *pmeth, int (*verify_init) (EVP_PKEY_CTX *ctx),
     int (*verify) (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verify_recover
    (EVP_PKEY_METHOD *pmeth, int (*verify_recover_init) (EVP_PKEY_CTX *ctx),
     int (*verify_recover) (EVP_PKEY_CTX *ctx, unsigned char *sig,
                            size_t *siglen, const unsigned char *tbs,
                            size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_signctx
    (EVP_PKEY_METHOD *pmeth, int (*signctx_init) (EVP_PKEY_CTX *ctx,
                                                  EVP_MD_CTX *mctx),
     int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                     EVP_MD_CTX *mctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_verifyctx
    (EVP_PKEY_METHOD *pmeth, int (*verifyctx_init) (EVP_PKEY_CTX *ctx,
                                                    EVP_MD_CTX *mctx),
     int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                       EVP_MD_CTX *mctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_encrypt
    (EVP_PKEY_METHOD *pmeth, int (*encrypt_init) (EVP_PKEY_CTX *ctx),
     int (*encryptfn) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_decrypt
    (EVP_PKEY_METHOD *pmeth, int (*decrypt_init) (EVP_PKEY_CTX *ctx),
     int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_derive
    (EVP_PKEY_METHOD *pmeth, int (*derive_init) (EVP_PKEY_CTX *ctx),
     int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_ctrl
    (EVP_PKEY_METHOD *pmeth, int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                          void *p2),
     int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestsign
    (EVP_PKEY_METHOD *pmeth,
     int (*digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digestverify
    (EVP_PKEY_METHOD *pmeth,
     int (*digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_check
    (EVP_PKEY_METHOD *pmeth, int (*check) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_public_check
    (EVP_PKEY_METHOD *pmeth, int (*check) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_param_check
    (EVP_PKEY_METHOD *pmeth, int (*check) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_digest_custom
    (EVP_PKEY_METHOD *pmeth, int (*digest_custom) (EVP_PKEY_CTX *ctx,
                                                   EVP_MD_CTX *mctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_init
    (const EVP_PKEY_METHOD *pmeth, int (**pinit) (EVP_PKEY_CTX *ctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_copy
    (const EVP_PKEY_METHOD *pmeth, int (**pcopy) (EVP_PKEY_CTX *dst,
                                                  const EVP_PKEY_CTX *src));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_cleanup
    (const EVP_PKEY_METHOD *pmeth, void (**pcleanup) (EVP_PKEY_CTX *ctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_paramgen
    (const EVP_PKEY_METHOD *pmeth, int (**pparamgen_init) (EVP_PKEY_CTX *ctx),
     int (**pparamgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_keygen
    (const EVP_PKEY_METHOD *pmeth, int (**pkeygen_init) (EVP_PKEY_CTX *ctx),
     int (**pkeygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_sign
    (const EVP_PKEY_METHOD *pmeth, int (**psign_init) (EVP_PKEY_CTX *ctx),
     int (**psign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify
    (const EVP_PKEY_METHOD *pmeth, int (**pverify_init) (EVP_PKEY_CTX *ctx),
     int (**pverify) (EVP_PKEY_CTX *ctx, const unsigned char *sig,
                      size_t siglen, const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verify_recover
    (const EVP_PKEY_METHOD *pmeth,
     int (**pverify_recover_init) (EVP_PKEY_CTX *ctx),
     int (**pverify_recover) (EVP_PKEY_CTX *ctx, unsigned char *sig,
                              size_t *siglen, const unsigned char *tbs,
                              size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_signctx
    (const EVP_PKEY_METHOD *pmeth,
     int (**psignctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
     int (**psignctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                       EVP_MD_CTX *mctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_verifyctx
    (const EVP_PKEY_METHOD *pmeth,
     int (**pverifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
     int (**pverifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig,
                          int siglen, EVP_MD_CTX *mctx));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_encrypt
    (const EVP_PKEY_METHOD *pmeth, int (**pencrypt_init) (EVP_PKEY_CTX *ctx),
     int (**pencryptfn) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                         const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_decrypt
    (const EVP_PKEY_METHOD *pmeth, int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
     int (**pdecrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_derive
    (const EVP_PKEY_METHOD *pmeth, int (**pderive_init) (EVP_PKEY_CTX *ctx),
     int (**pderive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_ctrl
    (const EVP_PKEY_METHOD *pmeth,
     int (**pctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
     int (**pctrl_str) (EVP_PKEY_CTX *ctx, const char *type,
                        const char *value));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestsign
    (const EVP_PKEY_METHOD *pmeth,
     int (**digestsign) (EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digestverify
    (const EVP_PKEY_METHOD *pmeth,
     int (**digestverify) (EVP_MD_CTX *ctx, const unsigned char *sig,
                           size_t siglen, const unsigned char *tbs,
                           size_t tbslen));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_check
    (const EVP_PKEY_METHOD *pmeth, int (**pcheck) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_public_check
    (const EVP_PKEY_METHOD *pmeth, int (**pcheck) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_param_check
    (const EVP_PKEY_METHOD *pmeth, int (**pcheck) (EVP_PKEY *pkey));
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get_digest_custom
    (const EVP_PKEY_METHOD *pmeth,
     int (**pdigest_custom) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx));

OSSL_DEPRECATEDIN_3_0
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                                size_t len, const EVP_CIPHER *cipher);
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);
OSSL_DEPRECATEDIN_3_0 EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags);
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                                              const EVP_PKEY_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,
                                         const EVP_PKEY_METHOD *src);
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth);
OSSL_DEPRECATEDIN_3_0 size_t EVP_PKEY_meth_get_count(void);
OSSL_DEPRECATEDIN_3_0 const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx);

OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_decrypt_old(unsigned char *dec_key,
                                               const unsigned char *enc_key,
                                               int enc_key_len,
                                               EVP_PKEY *private_key);
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_encrypt_old(unsigned char *enc_key,
                                               const unsigned char *key,
                                               int key_len, EVP_PKEY *pub_key);

#  ifndef OPENSSL_NO_ENGINE
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);
OSSL_DEPRECATEDIN_3_0
ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey);
#  endif

OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
OSSL_DEPRECATEDIN_3_0
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);

#  ifndef OPENSSL_NO_POLY1305
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len);
#  endif

#  ifndef OPENSSL_NO_SIPHASH
OSSL_DEPRECATEDIN_3_0
const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len);
#  endif

struct rsa_st;
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
OSSL_DEPRECATEDIN_3_0
const struct rsa_st *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);

#  ifndef OPENSSL_NO_DSA
struct dsa_st;
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, struct dsa_st *key);
OSSL_DEPRECATEDIN_3_0
const struct dsa_st *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
#  endif

#  ifndef OPENSSL_NO_DH
struct dh_st;
OSSL_DEPRECATEDIN_3_0 int EVP_PKEY_set1_DH(EVP_PKEY *pkey, struct dh_st *key);
OSSL_DEPRECATEDIN_3_0 const struct dh_st *EVP_PKEY_get0_DH(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0 struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
#  endif

#  ifndef OPENSSL_NO_EC
struct ec_key_st;
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
OSSL_DEPRECATEDIN_3_0
const struct ec_key_st *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
OSSL_DEPRECATEDIN_3_0
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
#  endif

/*
 * For backwards compatibility. Use EVP_PKEY_get1_encoded_public_key in
 * preference
 */
#  define EVP_PKEY_get1_tls_encodedpoint(pkey, ppt) \
          EVP_PKEY_get1_encoded_public_key((pkey), (ppt))
/*
 * For backwards compatibility. Use EVP_PKEY_set1_encoded_public_key in
 * preference
 */
#  define EVP_PKEY_set1_tls_encodedpoint(pkey, pt, ptlen) \
          EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))

OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
OSSL_DEPRECATEDIN_3_0
int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

# endif /* OPENSSL_NO_DEPRECATED_3_0 */


# ifndef OPENSSL_NO_DEPRECATED_1_1_0
#  define OPENSSL_add_all_algorithms_conf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define OPENSSL_add_all_algorithms_noconf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  ifdef OPENSSL_LOAD_CONF
#   define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_conf()
#  else
#   define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_noconf()
#  endif

#  define OpenSSL_add_all_ciphers() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#  define OpenSSL_add_all_digests() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  define EVP_cleanup() while(0) continue
# endif /* OPENSSL_NO_DEPRECATED_1_1_0 */

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_EVP_DEPRECATED_H */
