/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EVP_DIGEST_H
# define OPENSSL_EVP_DIGEST_H
# pragma once

# include <openssl/core.h>
# include <openssl/objects.h>

# ifdef __cplusplus
extern "C" {
# endif

# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */

# define EVP_PKEY_MO_SIGN        0x0001
# define EVP_PKEY_MO_VERIFY      0x0002
# define EVP_PKEY_MO_ENCRYPT     0x0004
# define EVP_PKEY_MO_DECRYPT     0x0008

# ifndef EVP_MD
/* digest can only handle a single block */
#  define EVP_MD_FLAG_ONESHOT     0x0001

/* digest is extensible-output function, XOF */
#  define EVP_MD_FLAG_XOF         0x0002

/* DigestAlgorithmIdentifier flags... */

#  define EVP_MD_FLAG_DIGALGID_MASK               0x0018

/* NULL or absent parameter accepted. Use NULL */

#  define EVP_MD_FLAG_DIGALGID_NULL               0x0000

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

#  define EVP_MD_FLAG_DIGALGID_ABSENT             0x0008

/* Custom handling via ctrl */

#  define EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018

/* Note if suitable for use in FIPS mode */
#  define EVP_MD_FLAG_FIPS        0x0400

/* Digest ctrls */

#  define EVP_MD_CTRL_DIGALGID                    0x1
#  define EVP_MD_CTRL_MICALG                      0x2
#  define EVP_MD_CTRL_XOF_LEN                     0x3
#  define EVP_MD_CTRL_TLSTREE                     0x4

/* Minimum Algorithm specific ctrl value */

#  define EVP_MD_CTRL_ALG_CTRL                    0x1000

# endif                         /* !EVP_MD */

/* values for EVP_MD_CTX flags */

# define EVP_MD_CTX_FLAG_ONESHOT         0x0001/* digest update will be
                                                * called once only */
# define EVP_MD_CTX_FLAG_CLEANED         0x0002/* context has already been
                                                * cleaned */
# define EVP_MD_CTX_FLAG_REUSE           0x0004/* Don't free up ctx->md_data
                                                * in EVP_MD_CTX_reset */
/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here so we
 * don't accidentally reuse the values for other purposes.
 */

/* This flag has no effect from openssl-3.0 onwards */
# define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW  0x0008

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */
# define EVP_MD_CTX_FLAG_PAD_MASK        0xF0/* RSA mode to use */
# define EVP_MD_CTX_FLAG_PAD_PKCS1       0x00/* PKCS#1 v1.5 mode */
# define EVP_MD_CTX_FLAG_PAD_X931        0x10/* X9.31 mode */
# define EVP_MD_CTX_FLAG_PAD_PSS         0x20/* PSS mode */

# define EVP_MD_CTX_FLAG_NO_INIT         0x0100/* Don't initialize md_data */
/*
 * Some functions such as EVP_DigestSign only finalise copies of internal
 * contexts so additional data can be included after the finalisation call.
 * This is inefficient if this functionality is not required: it is disabled
 * if the following flag is set.
 */
# define EVP_MD_CTX_FLAG_FINALISE        0x0200
/* NOTE: 0x0400 is reserved for internal usage */

/* Add some extra combinations */
# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))

int EVP_MD_get_type(const EVP_MD *md);
# define EVP_MD_type EVP_MD_get_type
# define EVP_MD_nid EVP_MD_get_type
const char *EVP_MD_get0_name(const EVP_MD *md);
# define EVP_MD_name EVP_MD_get0_name
const char *EVP_MD_get0_description(const EVP_MD *md);
int EVP_MD_is_a(const EVP_MD *md, const char *name);
int EVP_MD_names_do_all(const EVP_MD *md,
                        void (*fn)(const char *name, void *data),
                        void *data);
const OSSL_PROVIDER *EVP_MD_get0_provider(const EVP_MD *md);
int EVP_MD_get_pkey_type(const EVP_MD *md);
# define EVP_MD_pkey_type EVP_MD_get_pkey_type
int EVP_MD_get_size(const EVP_MD *md);
# define EVP_MD_size EVP_MD_get_size
int EVP_MD_get_block_size(const EVP_MD *md);
# define EVP_MD_block_size EVP_MD_get_block_size
unsigned long EVP_MD_get_flags(const EVP_MD *md);
# define EVP_MD_flags EVP_MD_get_flags

const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx);
EVP_MD *EVP_MD_CTX_get1_md(EVP_MD_CTX *ctx);

# define EVP_MD_CTX_get0_name(e)       EVP_MD_get0_name(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_get_size(e)        EVP_MD_get_size(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_size               EVP_MD_CTX_get_size
# define EVP_MD_CTX_get_block_size(e)  EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_block_size EVP_MD_CTX_get_block_size
# define EVP_MD_CTX_get_type(e)            EVP_MD_get_type(EVP_MD_CTX_get0_md(e))
# define EVP_MD_CTX_type EVP_MD_CTX_get_type
EVP_PKEY_CTX *EVP_MD_CTX_get_pkey_ctx(const EVP_MD_CTX *ctx);
# define EVP_MD_CTX_pkey_ctx EVP_MD_CTX_get_pkey_ctx
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
void *EVP_MD_CTX_get0_md_data(const EVP_MD_CTX *ctx);
# define EVP_MD_CTX_md_data EVP_MD_CTX_get0_md_data

int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[]);
int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[]);
int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *EVP_MD_gettable_params(const EVP_MD *digest);
const OSSL_PARAM *EVP_MD_settable_ctx_params(const EVP_MD *md);
const OSSL_PARAM *EVP_MD_gettable_ctx_params(const EVP_MD *md);
const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx);
const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx);
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
__owur EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in);
__owur int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);
__owur int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type,
                              const OSSL_PARAM params[]);
__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl);
__owur int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
__owur int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
__owur int EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVP_MD *type, ENGINE *impl);
__owur int EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name,
                        const char *propq, const void *data, size_t datalen,
                        unsigned char *md, size_t *mdlen);

__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);
__owur int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md,
                              size_t len);

__owur EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                            const char *properties);

int EVP_MD_up_ref(EVP_MD *md);
void EVP_MD_free(EVP_MD *md);

__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey);
__owur int EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                            EVP_PKEY *pkey, OSSL_LIB_CTX *libctx,
                            const char *propq);

__owur int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
                          size_t *siglen, const unsigned char *tbs,
                          size_t tbslen);

__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey);
__owur int EVP_VerifyFinal_ex(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                              unsigned int siglen, EVP_PKEY *pkey,
                              OSSL_LIB_CTX *libctx, const char *propq);

__owur int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen);

__owur int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                 const char *mdname, OSSL_LIB_CTX *libctx,
                                 const char *props, EVP_PKEY *pkey,
                                 const OSSL_PARAM params[]);
__owur int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                              const EVP_MD *type, ENGINE *e,
                              EVP_PKEY *pkey);
__owur int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t dsize);
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

__owur int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                   const char *mdname, OSSL_LIB_CTX *libctx,
                                   const char *props, EVP_PKEY *pkey,
                                   const OSSL_PARAM params[]);
__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *type, ENGINE *e,
                                EVP_PKEY *pkey);
int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t dsize);
__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen);

# define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
# define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
# define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)
# define EVP_VerifyInit_ex(a,b,c)        EVP_DigestInit_ex(a,b,c)
# define EVP_VerifyInit(a,b)             EVP_DigestInit(a,b)
# define EVP_VerifyUpdate(a,b,c)         EVP_DigestUpdate(a,b,c)

void EVP_MD_do_all_provided(OSSL_LIB_CTX *libctx,
                            void (*fn)(EVP_MD *md, void *arg),
                            void *arg);

# define EVP_add_digest_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
# define EVP_delete_digest_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

const EVP_MD *EVP_get_digestbyname(const char *name);
int EVP_add_digest(const EVP_MD *digest);

void EVP_MD_do_all(void (*fn) (const EVP_MD *ciph,
                               const char *from, const char *to, void *x),
                   void *arg);
void EVP_MD_do_all_sorted(void (*fn)
                           (const EVP_MD *ciph, const char *from,
                            const char *to, void *x), void *arg);

/* Old constant EVP_MD method tables. */

const EVP_MD *EVP_md_null(void);
# ifndef OPENSSL_NO_MD2
const EVP_MD *EVP_md2(void);
# endif
# ifndef OPENSSL_NO_MD4
const EVP_MD *EVP_md4(void);
# endif
# ifndef OPENSSL_NO_MD5
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_md5_sha1(void);
# endif
# ifndef OPENSSL_NO_BLAKE2
const EVP_MD *EVP_blake2b512(void);
const EVP_MD *EVP_blake2s256(void);
# endif
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sha512_224(void);
const EVP_MD *EVP_sha512_256(void);
const EVP_MD *EVP_sha3_224(void);
const EVP_MD *EVP_sha3_256(void);
const EVP_MD *EVP_sha3_384(void);
const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);

# ifndef OPENSSL_NO_MDC2
const EVP_MD *EVP_mdc2(void);
# endif
# ifndef OPENSSL_NO_RMD160
const EVP_MD *EVP_ripemd160(void);
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
const EVP_MD *EVP_whirlpool(void);
# endif
# ifndef OPENSSL_NO_SM3
const EVP_MD *EVP_sm3(void);
# endif

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_EVP_DIGEST_H */
