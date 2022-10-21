/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_EVP_CIPHER_H
# define OPENSSL_EVP_CIPHER_H
# pragma once

# include <openssl/core.h>
# include <openssl/objects.h>

# ifdef __cplusplus
extern "C" {
# endif

# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32

/* Modes for ciphers */
# define         EVP_CIPH_STREAM_CIPHER          0x0
# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_CTR_MODE               0x5
# define         EVP_CIPH_GCM_MODE               0x6
# define         EVP_CIPH_CCM_MODE               0x7
# define         EVP_CIPH_XTS_MODE               0x10001
# define         EVP_CIPH_WRAP_MODE              0x10002
# define         EVP_CIPH_OCB_MODE               0x10003
# define         EVP_CIPH_SIV_MODE               0x10004
# define         EVP_CIPH_GCM_SIV_MODE           0x10005
# define         EVP_CIPH_MODE                   0xF0007
/* Set if variable length cipher */
# define         EVP_CIPH_VARIABLE_LENGTH        0x8
/* Set if the iv handling should be done by the cipher itself */
# define         EVP_CIPH_CUSTOM_IV              0x10
/* Set if the cipher's init() function should be called if key is NULL */
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20
/* Call ctrl() to init cipher parameters */
# define         EVP_CIPH_CTRL_INIT              0x40
/* Don't use standard key length function */
# define         EVP_CIPH_CUSTOM_KEY_LENGTH      0x80
/* Don't use standard block padding */
# define         EVP_CIPH_NO_PADDING             0x100
/* cipher handles random key generation */
# define         EVP_CIPH_RAND_KEY               0x200
/* cipher has its own additional copying logic */
# define         EVP_CIPH_CUSTOM_COPY            0x400
/* Don't use standard iv length function */
# define         EVP_CIPH_CUSTOM_IV_LENGTH       0x800
/* Legacy and no longer relevant: Allow use default ASN1 get/set iv */
# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0
/* Free:                                         0x1000 */
/* Buffer length in bits not bytes: CFB1 mode only */
# define         EVP_CIPH_FLAG_LENGTH_BITS       0x2000
/* Deprecated FIPS flag: was 0x4000 */
# define         EVP_CIPH_FLAG_FIPS              0
/* Deprecated FIPS flag: was 0x8000 */
# define         EVP_CIPH_FLAG_NON_FIPS_ALLOW    0

/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
# define         EVP_CIPH_FLAG_CTS               0x4000
# define         EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define         EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
/* Cipher can handle pipeline operations */
# define         EVP_CIPH_FLAG_PIPELINE          0X800000
/* For provider implementations that handle  ASN1 get/set param themselves */
# define         EVP_CIPH_FLAG_CUSTOM_ASN1       0x1000000
/* For ciphers generating unprotected CMS attributes */
# define         EVP_CIPH_FLAG_CIPHER_WITH_MAC   0x2000000
/* For supplementary wrap cipher support */
# define         EVP_CIPH_FLAG_GET_WRAP_CIPHER   0x4000000
# define         EVP_CIPH_FLAG_INVERSE_CIPHER    0x8000000

/*
 * Cipher context flag to indicate we can handle wrap mode: if allowed in
 * older applications it could overflow buffers.
 */

# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1

/* ctrl() values */
# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVP_CTRL_SET_RC5_ROUNDS         0x5
# define         EVP_CTRL_RAND_KEY               0x6
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_COPY                   0x8
# define         EVP_CTRL_AEAD_SET_IVLEN         0x9
# define         EVP_CTRL_AEAD_GET_TAG           0x10
# define         EVP_CTRL_AEAD_SET_TAG           0x11
# define         EVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_GCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_GCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_GCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_GCM_IV_GEN             0x13
# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_CCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_CCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_CCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_CCM_SET_L              0x14
# define         EVP_CTRL_CCM_SET_MSGLEN         0x15
/*
 * AEAD cipher deduces payload length and returns number of bytes required to
 * store MAC and eventual padding. Subsequent call to EVP_Cipher even
 * appends/verifies MAC.
 */
# define         EVP_CTRL_AEAD_TLS1_AAD          0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
# define         EVP_CTRL_AEAD_SET_MAC_KEY       0x17
/* Set the GCM invocation field, decrypt only */
# define         EVP_CTRL_GCM_SET_IV_INV         0x18

# define         EVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c

# define         EVP_CTRL_SSL3_MASTER_SECRET             0x1d

/* EVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
# define         EVP_CTRL_SET_SBOX                       0x1e
/*
 * EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
# define         EVP_CTRL_SBOX_USED                      0x1f
/* EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
# define         EVP_CTRL_KEY_MESH                       0x20
/* EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
# define         EVP_CTRL_BLOCK_PADDING_MODE             0x21

/* Set the output buffers to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS       0x22
/* Set the input buffers to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_INPUT_BUFS        0x23
/* Set the input buffer lengths to use for a pipelined operation */
# define         EVP_CTRL_SET_PIPELINE_INPUT_LENS        0x24
/* Get the IV length used by the cipher */
# define         EVP_CTRL_GET_IVLEN                      0x25
/* 0x26 is unused */
/* Tell the cipher it's doing a speed test (SIV disallows multiple ops) */
# define         EVP_CTRL_SET_SPEED                      0x27
/* Get the unprotectedAttrs from cipher ctx */
# define         EVP_CTRL_PROCESS_UNPROTECTED            0x28
/* Get the supplementary wrap cipher */
#define          EVP_CTRL_GET_WRAP_CIPHER                0x29
/* TLSTREE key diversification */
#define          EVP_CTRL_TLSTREE                        0x2A

/* Padding modes */
#define EVP_PADDING_PKCS7       1
#define EVP_PADDING_ISO7816_4   2
#define EVP_PADDING_ANSI923     3
#define EVP_PADDING_ISO10126    4
#define EVP_PADDING_ZERO        5

/* RFC 5246 defines additional data to be 13 bytes in length */
# define         EVP_AEAD_TLS1_AAD_LEN           13

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVP_GCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVP_GCM_TLS_EXPLICIT_IV_LEN                     8
/* Length of tag for TLS */
# define EVP_GCM_TLS_TAG_LEN                             16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVP_CCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
/* Total length of CCM IV length for TLS */
# define EVP_CCM_TLS_IV_LEN                              12
/* Length of tag for TLS */
# define EVP_CCM_TLS_TAG_LEN                             16
/* Length of CCM8 tag for TLS */
# define EVP_CCM8_TLS_TAG_LEN                            8

/* Length of tag for TLS */
# define EVP_CHACHAPOLY_TLS_TAG_LEN                      16

# ifdef __cplusplus
extern "C" {
# endif

typedef struct {
    unsigned char *out;
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

typedef struct evp_cipher_info_st {
    const EVP_CIPHER *cipher;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;

/* Add some extra combinations */
# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

int EVP_CIPHER_get_nid(const EVP_CIPHER *cipher);
# define EVP_CIPHER_nid EVP_CIPHER_get_nid
const char *EVP_CIPHER_get0_name(const EVP_CIPHER *cipher);
# define EVP_CIPHER_name EVP_CIPHER_get0_name
const char *EVP_CIPHER_get0_description(const EVP_CIPHER *cipher);
int EVP_CIPHER_is_a(const EVP_CIPHER *cipher, const char *name);
int EVP_CIPHER_names_do_all(const EVP_CIPHER *cipher,
                            void (*fn)(const char *name, void *data),
                            void *data);
const OSSL_PROVIDER *EVP_CIPHER_get0_provider(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);
# define EVP_CIPHER_block_size EVP_CIPHER_get_block_size

int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);
# define EVP_CIPHER_key_length EVP_CIPHER_get_key_length
int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);
# define EVP_CIPHER_iv_length EVP_CIPHER_get_iv_length
unsigned long EVP_CIPHER_get_flags(const EVP_CIPHER *cipher);
# define EVP_CIPHER_flags EVP_CIPHER_get_flags
int EVP_CIPHER_get_mode(const EVP_CIPHER *cipher);
# define EVP_CIPHER_mode EVP_CIPHER_get_mode
int EVP_CIPHER_get_type(const EVP_CIPHER *cipher);
# define EVP_CIPHER_type EVP_CIPHER_get_type
EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                             const char *properties);
int EVP_CIPHER_up_ref(EVP_CIPHER *cipher);
void EVP_CIPHER_free(EVP_CIPHER *cipher);

const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx);
EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_encrypting EVP_CIPHER_CTX_is_encrypting
int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_nid EVP_CIPHER_CTX_get_nid
int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_block_size EVP_CIPHER_CTX_get_block_size
int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_key_length EVP_CIPHER_CTX_get_key_length
int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_iv_length EVP_CIPHER_CTX_get_iv_length
int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_tag_length EVP_CIPHER_CTX_get_tag_length

int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);
int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len);

int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx);
# define EVP_CIPHER_CTX_num EVP_CIPHER_CTX_get_num
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
# define EVP_CIPHER_CTX_get0_name(c) EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_get_type(c)  EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_type         EVP_CIPHER_CTX_get_type
# define EVP_CIPHER_CTX_get_mode(c)  EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))
# define EVP_CIPHER_CTX_mode         EVP_CIPHER_CTX_get_mode

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags);

__owur int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
__owur int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                              const EVP_CIPHER *cipher, ENGINE *impl,
                              const unsigned char *key,
                              const unsigned char *iv);
__owur int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                               const unsigned char *key,
                               const unsigned char *iv,
                               const OSSL_PARAM params[]);
__owur int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             int *outl, const unsigned char *in, int inl);
__owur int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               int *outl);
__owur int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl);

__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
__owur int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                              const EVP_CIPHER *cipher, ENGINE *impl,
                              const unsigned char *key,
                              const unsigned char *iv);
__owur int EVP_DecryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                               const unsigned char *key,
                               const unsigned char *iv,
                               const OSSL_PARAM params[]);
__owur int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             int *outl, const unsigned char *in, int inl);
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
__owur int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                               int *outl);

__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
__owur int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                             const EVP_CIPHER *cipher, ENGINE *impl,
                             const unsigned char *key,
                             const unsigned char *iv, int enc);
__owur int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                              const unsigned char *key, const unsigned char *iv,
                              int enc, const OSSL_PARAM params[]);
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);
__owur int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        const unsigned char *ek, int ekl,
                        const unsigned char *iv, EVP_PKEY *priv);
__owur int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

__owur int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        unsigned char **ek, int *ekl, unsigned char *iv,
                        EVP_PKEY **pubk, int npubk);
__owur int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

# define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
# define EVP_SealUpdate(a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
int EVP_CIPHER_get_params(EVP_CIPHER *cipher, OSSL_PARAM params[]);
int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *EVP_CIPHER_gettable_params(const EVP_CIPHER *cipher);
const OSSL_PARAM *EVP_CIPHER_settable_ctx_params(const EVP_CIPHER *cipher);
const OSSL_PARAM *EVP_CIPHER_gettable_ctx_params(const EVP_CIPHER *cipher);
const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *ctx);
const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *ctx);

__owur int EVP_Cipher(EVP_CIPHER_CTX *c,
                      unsigned char *out,
                      const unsigned char *in, unsigned int inl);

void EVP_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx,
                                void (*fn)(EVP_CIPHER *cipher, void *arg),
                                void *arg);

/* calls methods */
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* These are used by EVP_CIPHER methods */
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

# define EVP_add_cipher_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
# define EVP_delete_cipher_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
int EVP_add_cipher(const EVP_CIPHER *cipher);

void EVP_CIPHER_do_all(void (*fn) (const EVP_CIPHER *ciph,
                                   const char *from, const char *to, void *x),
                       void *arg);
void EVP_CIPHER_do_all_sorted(void (*fn)
                               (const EVP_CIPHER *ciph, const char *from,
                                const char *to, void *x), void *arg);


/* Old constant EVP_CIPHER method tables. */

const EVP_CIPHER *EVP_enc_null(void); /* does nothing :-) */
# ifndef OPENSSL_NO_DES
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);
#  define EVP_des_cfb EVP_des_cfb64
const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
#  define EVP_des_ede_cfb EVP_des_ede_cfb64
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
#  define EVP_des_ede3_cfb EVP_des_ede3_cfb64
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
const EVP_CIPHER *EVP_des_ede3_wrap(void);
/*
 * This should now be supported through the dev_crypto ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
# endif
# ifndef OPENSSL_NO_RC4
const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);
#  ifndef OPENSSL_NO_MD5
const EVP_CIPHER *EVP_rc4_hmac_md5(void);
#  endif
# endif
# ifndef OPENSSL_NO_IDEA
const EVP_CIPHER *EVP_idea_ecb(void);
const EVP_CIPHER *EVP_idea_cfb64(void);
#  define EVP_idea_cfb EVP_idea_cfb64
const EVP_CIPHER *EVP_idea_ofb(void);
const EVP_CIPHER *EVP_idea_cbc(void);
# endif
# ifndef OPENSSL_NO_RC2
const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);
#  define EVP_rc2_cfb EVP_rc2_cfb64
const EVP_CIPHER *EVP_rc2_ofb(void);
# endif
# ifndef OPENSSL_NO_BF
const EVP_CIPHER *EVP_bf_ecb(void);
const EVP_CIPHER *EVP_bf_cbc(void);
const EVP_CIPHER *EVP_bf_cfb64(void);
#  define EVP_bf_cfb EVP_bf_cfb64
const EVP_CIPHER *EVP_bf_ofb(void);
# endif
# ifndef OPENSSL_NO_CAST
const EVP_CIPHER *EVP_cast5_ecb(void);
const EVP_CIPHER *EVP_cast5_cbc(void);
const EVP_CIPHER *EVP_cast5_cfb64(void);
#  define EVP_cast5_cfb EVP_cast5_cfb64
const EVP_CIPHER *EVP_cast5_ofb(void);
# endif
# ifndef OPENSSL_NO_RC5
const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void);
#  define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
# endif
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
# define EVP_aes_128_cfb EVP_aes_128_cfb128
const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_128_ccm(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_128_xts(void);
const EVP_CIPHER *EVP_aes_128_wrap(void);
const EVP_CIPHER *EVP_aes_128_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_128_ocb(void);
# endif
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
# define EVP_aes_192_cfb EVP_aes_192_cfb128
const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_192_ccm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_192_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_192_ocb(void);
# endif
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
# define EVP_aes_256_cfb EVP_aes_256_cfb128
const EVP_CIPHER *EVP_aes_256_ofb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
const EVP_CIPHER *EVP_aes_256_ccm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_256_xts(void);
const EVP_CIPHER *EVP_aes_256_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_256_ocb(void);
# endif
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void);
# ifndef OPENSSL_NO_ARIA
const EVP_CIPHER *EVP_aria_128_ecb(void);
const EVP_CIPHER *EVP_aria_128_cbc(void);
const EVP_CIPHER *EVP_aria_128_cfb1(void);
const EVP_CIPHER *EVP_aria_128_cfb8(void);
const EVP_CIPHER *EVP_aria_128_cfb128(void);
#  define EVP_aria_128_cfb EVP_aria_128_cfb128
const EVP_CIPHER *EVP_aria_128_ctr(void);
const EVP_CIPHER *EVP_aria_128_ofb(void);
const EVP_CIPHER *EVP_aria_128_gcm(void);
const EVP_CIPHER *EVP_aria_128_ccm(void);
const EVP_CIPHER *EVP_aria_192_ecb(void);
const EVP_CIPHER *EVP_aria_192_cbc(void);
const EVP_CIPHER *EVP_aria_192_cfb1(void);
const EVP_CIPHER *EVP_aria_192_cfb8(void);
const EVP_CIPHER *EVP_aria_192_cfb128(void);
#  define EVP_aria_192_cfb EVP_aria_192_cfb128
const EVP_CIPHER *EVP_aria_192_ctr(void);
const EVP_CIPHER *EVP_aria_192_ofb(void);
const EVP_CIPHER *EVP_aria_192_gcm(void);
const EVP_CIPHER *EVP_aria_192_ccm(void);
const EVP_CIPHER *EVP_aria_256_ecb(void);
const EVP_CIPHER *EVP_aria_256_cbc(void);
const EVP_CIPHER *EVP_aria_256_cfb1(void);
const EVP_CIPHER *EVP_aria_256_cfb8(void);
const EVP_CIPHER *EVP_aria_256_cfb128(void);
#  define EVP_aria_256_cfb EVP_aria_256_cfb128
const EVP_CIPHER *EVP_aria_256_ctr(void);
const EVP_CIPHER *EVP_aria_256_ofb(void);
const EVP_CIPHER *EVP_aria_256_gcm(void);
const EVP_CIPHER *EVP_aria_256_ccm(void);
# endif
# ifndef OPENSSL_NO_CAMELLIA
const EVP_CIPHER *EVP_camellia_128_ecb(void);
const EVP_CIPHER *EVP_camellia_128_cbc(void);
const EVP_CIPHER *EVP_camellia_128_cfb1(void);
const EVP_CIPHER *EVP_camellia_128_cfb8(void);
const EVP_CIPHER *EVP_camellia_128_cfb128(void);
#  define EVP_camellia_128_cfb EVP_camellia_128_cfb128
const EVP_CIPHER *EVP_camellia_128_ofb(void);
const EVP_CIPHER *EVP_camellia_128_ctr(void);
const EVP_CIPHER *EVP_camellia_192_ecb(void);
const EVP_CIPHER *EVP_camellia_192_cbc(void);
const EVP_CIPHER *EVP_camellia_192_cfb1(void);
const EVP_CIPHER *EVP_camellia_192_cfb8(void);
const EVP_CIPHER *EVP_camellia_192_cfb128(void);
#  define EVP_camellia_192_cfb EVP_camellia_192_cfb128
const EVP_CIPHER *EVP_camellia_192_ofb(void);
const EVP_CIPHER *EVP_camellia_192_ctr(void);
const EVP_CIPHER *EVP_camellia_256_ecb(void);
const EVP_CIPHER *EVP_camellia_256_cbc(void);
const EVP_CIPHER *EVP_camellia_256_cfb1(void);
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
const EVP_CIPHER *EVP_camellia_256_cfb128(void);
#  define EVP_camellia_256_cfb EVP_camellia_256_cfb128
const EVP_CIPHER *EVP_camellia_256_ofb(void);
const EVP_CIPHER *EVP_camellia_256_ctr(void);
# endif
# ifndef OPENSSL_NO_CHACHA
const EVP_CIPHER *EVP_chacha20(void);
#  ifndef OPENSSL_NO_POLY1305
const EVP_CIPHER *EVP_chacha20_poly1305(void);
#  endif
# endif

# ifndef OPENSSL_NO_SEED
const EVP_CIPHER *EVP_seed_ecb(void);
const EVP_CIPHER *EVP_seed_cbc(void);
const EVP_CIPHER *EVP_seed_cfb128(void);
#  define EVP_seed_cfb EVP_seed_cfb128
const EVP_CIPHER *EVP_seed_ofb(void);
# endif

# ifndef OPENSSL_NO_SM4
const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);
#  define EVP_sm4_cfb EVP_sm4_cfb128
const EVP_CIPHER *EVP_sm4_ofb(void);
const EVP_CIPHER *EVP_sm4_ctr(void);
# endif

# ifdef __cplusplus
}
# endif
#endif /* OPENSSL_EVP_CIPHER_H */
