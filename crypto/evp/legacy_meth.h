/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define IMPLEMENT_LEGACY_EVP_MD_METH(nm, fn)                                   \
static int nm##_init(EVP_MD_CTX *ctx)                                          \
{                                                                              \
    return fn##_Init(EVP_MD_CTX_md_data(ctx));                                 \
}                                                                              \
static int nm##_update(EVP_MD_CTX *ctx, const void *data, size_t count)        \
{                                                                              \
    return fn##_Update(EVP_MD_CTX_md_data(ctx), data, count);                  \
}                                                                              \
static int nm##_final(EVP_MD_CTX *ctx, unsigned char *md)                      \
{                                                                              \
    return fn##_Final(md, EVP_MD_CTX_md_data(ctx));                            \
}

#define IMPLEMENT_LEGACY_EVP_MD_METH_LC(nm, fn)                                \
static int nm##_init(EVP_MD_CTX *ctx)                                          \
{                                                                              \
    return fn##_init(EVP_MD_CTX_md_data(ctx));                                 \
}                                                                              \
static int nm##_update(EVP_MD_CTX *ctx, const void *data, size_t count)        \
{                                                                              \
    return fn##_update(EVP_MD_CTX_md_data(ctx), data, count);                  \
}                                                                              \
static int nm##_final(EVP_MD_CTX *ctx, unsigned char *md)                      \
{                                                                              \
    return fn##_final(md, EVP_MD_CTX_md_data(ctx));                            \
}


#define LEGACY_EVP_MD_METH_TABLE(init, update, final, ctrl, blksz)             \
    init, update, final, NULL, NULL, blksz, 0, ctrl

void legacy_evp_cipher_set_nid(const char *name, void *vlegacy_nid);
int legacy_evp_cipher_ctx_reset(EVP_CIPHER_CTX *ctx, int *ret);
int legacy_evp_cipher_ctx_set_key_length(EVP_CIPHER_CTX *c, int keylen,
                                         int *ret);
int legacy_evp_cipher_ctx_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                               void *ptr, int *ret);
int legacy_evp_cipher_ctx_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in,
                               int *ret);

int legacy_evp_cipher_init_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                              ENGINE *impl, const unsigned char *key,
                              const unsigned char *iv, int enc, int *ret);
int legacy_evp_encrypt_update(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl,
                              int *ret);
int legacy_evp_encrypt_final_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, int *res);
int legacy_evp_decrypt_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl, int *res);
int legacy_evp_decrypt_final_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, int *ret);

void legacy_evp_digest_set_nid(const char *name, void *vlegacy_nid);
void legacy_evp_md_ctx_reset(EVP_MD_CTX *ctx);
int legacy_evp_md_ctx_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in, int *ret);
int legacy_evp_md_ctx_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2, int *ret);

int legacy_evp_digest_init_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl,
                              int *ret);
int legacy_evp_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count,
                             int *ret);
int legacy_evp_digest_final_ex(EVP_MD_CTX *ctx, unsigned char *md,
                               unsigned int *isize, int *ret);
int legacy_evp_digest_final_xof(EVP_MD_CTX *ctx, unsigned char *md, size_t size,
                                int *ret);
