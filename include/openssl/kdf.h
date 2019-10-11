/*
 * Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_KDF_H
# define OPENSSL_KDF_H
# pragma once

# include <openssl/macros.h>
# if !OPENSSL_API_3
#  define HEADER_KDF_H
# endif

# include <stdarg.h>
# include <stddef.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

int EVP_KDF_up_ref(EVP_KDF *kdf);
void EVP_KDF_free(EVP_KDF *kdf);
EVP_KDF *EVP_KDF_fetch(OPENSSL_CTX *libctx, const char *algorithm,
                       const char *properties);

EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf);
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);
EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src);
const char *EVP_KDF_name(const EVP_KDF *kdf);
const OSSL_PROVIDER *EVP_KDF_provider(const EVP_KDF *kdf);
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx);

void EVP_KDF_reset(EVP_KDF_CTX *ctx);
size_t EVP_KDF_size(EVP_KDF_CTX *ctx);
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen);
int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[]);
int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[]);
int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf);
const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf);
const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf);

void EVP_KDF_do_all_ex(OPENSSL_CTX *libctx,
                       void (*fn)(EVP_KDF *kdf, void *arg),
                       void *arg);

# define EVP_KDF_CTRL_SET_PASS               0x01 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_SALT               0x02 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_ITER               0x03 /* int */
# define EVP_KDF_CTRL_SET_MD                 0x04 /* EVP_MD * */
# define EVP_KDF_CTRL_SET_KEY                0x05 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_MAXMEM_BYTES       0x06 /* uint64_t */
# define EVP_KDF_CTRL_SET_TLS_SECRET         0x07 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_ADD_TLS_SEED           0x08 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_RESET_HKDF_INFO        0x09
# define EVP_KDF_CTRL_ADD_HKDF_INFO          0x0a /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_HKDF_MODE          0x0b /* int */
# define EVP_KDF_CTRL_SET_SCRYPT_N           0x0c /* uint64_t */
# define EVP_KDF_CTRL_SET_SCRYPT_R           0x0d /* uint32_t */
# define EVP_KDF_CTRL_SET_SCRYPT_P           0x0e /* uint32_t */
# define EVP_KDF_CTRL_SET_SSHKDF_XCGHASH     0x0f /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID  0x10 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_SSHKDF_TYPE        0x11 /* int */
# define EVP_KDF_CTRL_SET_MAC                0x12 /* EVP_MAC * */
# define EVP_KDF_CTRL_SET_MAC_SIZE           0x13 /* size_t */
# define EVP_KDF_CTRL_SET_SSKDF_INFO         0x14 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_PBKDF2_PKCS5_MODE  0x15 /* int */
# define EVP_KDF_CTRL_SET_UKM                0x16 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_CEK_ALG            0x17 /* char * */
# define EVP_KDF_CTRL_SET_SHARED_INFO        EVP_KDF_CTRL_SET_SSKDF_INFO

# define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND  0
# define EVP_KDF_HKDF_MODE_EXTRACT_ONLY        1
# define EVP_KDF_HKDF_MODE_EXPAND_ONLY         2

#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV     65
#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI     66
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV 67
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI 68
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV  69
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI  70

/**** The legacy PKEY-based KDF API follows. ****/

# define EVP_PKEY_CTRL_TLS_MD                   (EVP_PKEY_ALG_CTRL)
# define EVP_PKEY_CTRL_TLS_SECRET               (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_TLS_SEED                 (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_HKDF_MD                  (EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_HKDF_SALT                (EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_HKDF_KEY                 (EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_HKDF_INFO                (EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_HKDF_MODE                (EVP_PKEY_ALG_CTRL + 7)
# define EVP_PKEY_CTRL_PASS                     (EVP_PKEY_ALG_CTRL + 8)
# define EVP_PKEY_CTRL_SCRYPT_SALT              (EVP_PKEY_ALG_CTRL + 9)
# define EVP_PKEY_CTRL_SCRYPT_N                 (EVP_PKEY_ALG_CTRL + 10)
# define EVP_PKEY_CTRL_SCRYPT_R                 (EVP_PKEY_ALG_CTRL + 11)
# define EVP_PKEY_CTRL_SCRYPT_P                 (EVP_PKEY_ALG_CTRL + 12)
# define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (EVP_PKEY_ALG_CTRL + 13)

# define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND \
            EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
# define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       \
            EVP_KDF_HKDF_MODE_EXTRACT_ONLY
# define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY        \
            EVP_KDF_HKDF_MODE_EXPAND_ONLY

# define EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SECRET, seclen, (void *)(sec))

# define EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seedlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SEED, seedlen, (void *)(seed))

# define EVP_PKEY_CTX_set_hkdf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key))

# define EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info))

# define EVP_PKEY_CTX_hkdf_mode(pctx, mode) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MODE, mode, NULL)

# define EVP_PKEY_CTX_set1_pbe_pass(pctx, pass, passlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_PASS, passlen, (void *)(pass))

# define EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set_scrypt_N(pctx, n) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_N, n)

# define EVP_PKEY_CTX_set_scrypt_r(pctx, r) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_R, r)

# define EVP_PKEY_CTX_set_scrypt_p(pctx, p) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_P, p)

# define EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, maxmem_bytes) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, maxmem_bytes)


# ifdef __cplusplus
}
# endif
#endif
