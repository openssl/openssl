/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_RAND_H
# define OPENSSL_RAND_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_RAND_H
# endif

# include <stdlib.h>
# include <openssl/types.h>
# include <openssl/e_os2.h>
# include <openssl/randerr.h>
# include <openssl/evp.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Default security strength (in the sense of [NIST SP 800-90Ar1])
 *
 * NIST SP 800-90Ar1 supports the strength of the DRBG being smaller than that
 * of the cipher by collecting less entropy. The current DRBG implementation
 * does not take RAND_DRBG_STRENGTH into account and sets the strength of the
 * DRBG to that of the cipher.
 */
# define RAND_DRBG_STRENGTH             256

# ifndef OPENSSL_NO_DEPRECATED_3_0
struct rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};

OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_method(const RAND_METHOD *meth);
OSSL_DEPRECATEDIN_3_0 const RAND_METHOD *RAND_get_rand_method(void);
#  ifndef OPENSSL_NO_ENGINE
OSSL_DEPRECATEDIN_3_0 int RAND_set_rand_engine(ENGINE *engine);
#  endif

OSSL_DEPRECATEDIN_3_0 RAND_METHOD *RAND_OpenSSL(void);
# endif /* OPENSSL_NO_DEPRECATED_3_0 */

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
#   define RAND_cleanup() while(0) continue
# endif
int RAND_bytes(unsigned char *buf, int num);
int RAND_priv_bytes(unsigned char *buf, int num);

/*
 * Equivalent of RAND_priv_bytes() but additionally taking an OSSL_LIB_CTX and
 * a strength.
 */
int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                       unsigned int strength);

/*
 * Equivalent of RAND_bytes() but additionally taking an OSSL_LIB_CTX and
 * a strength.
 */
int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                  unsigned int strength);

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0 int RAND_pseudo_bytes(unsigned char *buf, int num);
# endif

EVP_RAND_CTX *RAND_get0_primary(OSSL_LIB_CTX *ctx);
EVP_RAND_CTX *RAND_get0_public(OSSL_LIB_CTX *ctx);
EVP_RAND_CTX *RAND_get0_private(OSSL_LIB_CTX *ctx);
int RAND_set0_public(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);
int RAND_set0_private(OSSL_LIB_CTX *ctx, EVP_RAND_CTX *rand);

int RAND_set_DRBG_type(OSSL_LIB_CTX *ctx, const char *drbg, const char *propq,
                       const char *cipher, const char *digest);
int RAND_set_seed_source_type(OSSL_LIB_CTX *ctx, const char *seed,
                              const char *propq);

void RAND_seed(const void *buf, int num);
void RAND_keep_random_devices_open(int keep);

# if defined(__ANDROID__) && defined(__NDK_FPABI__)
__NDK_FPABI__   /* __attribute__((pcs("aapcs"))) on ARM */
# endif
void RAND_add(const void *buf, int num, double randomness);
int RAND_load_file(const char *file, long max_bytes);
int RAND_write_file(const char *file);
const char *RAND_file_name(char *file, size_t num);
int RAND_status(void);

# ifndef OPENSSL_NO_EGD
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int RAND_egd(const char *path);
int RAND_egd_bytes(const char *path, int bytes);
# endif

int RAND_poll(void);

# if defined(_WIN32) && (defined(BASETYPES) || defined(_WINDEF_H))
/* application has to include <windows.h> in order to use these */
#  ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0 void RAND_screen(void);
OSSL_DEPRECATEDIN_1_1_0 int RAND_event(UINT, WPARAM, LPARAM);
#  endif
# endif

/* RAND stuff */
EVP_RAND *EVP_RAND_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
                         const char *properties);
int EVP_RAND_up_ref(EVP_RAND *rand);
void EVP_RAND_free(EVP_RAND *rand);
const char *EVP_RAND_get0_name(const EVP_RAND *rand);
const char *EVP_RAND_get0_description(const EVP_RAND *md);
int EVP_RAND_is_a(const EVP_RAND *rand, const char *name);
const OSSL_PROVIDER *EVP_RAND_get0_provider(const EVP_RAND *rand);
int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[]);

EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent);
int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx);
void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx);
EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx);
int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[]);
int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand);
const OSSL_PARAM *EVP_RAND_gettable_ctx_params(const EVP_RAND *rand);
const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand);
const OSSL_PARAM *EVP_RAND_CTX_gettable_params(EVP_RAND_CTX *ctx);
const OSSL_PARAM *EVP_RAND_CTX_settable_params(EVP_RAND_CTX *ctx);

void EVP_RAND_do_all_provided(OSSL_LIB_CTX *libctx,
                              void (*fn)(EVP_RAND *rand, void *arg),
                              void *arg);
int EVP_RAND_names_do_all(const EVP_RAND *rand,
                          void (*fn)(const char *name, void *data),
                          void *data);

__owur int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
                                int prediction_resistance,
                                const unsigned char *pstr, size_t pstr_len,
                                const OSSL_PARAM params[]);
int EVP_RAND_uninstantiate(EVP_RAND_CTX *ctx);
__owur int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out,
                             size_t outlen, unsigned int strength,
                             int prediction_resistance,
                             const unsigned char *addin, size_t addin_len);
int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
                    const unsigned char *ent, size_t ent_len,
                    const unsigned char *addin, size_t addin_len);
__owur int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen);
__owur int EVP_RAND_enable_locking(EVP_RAND_CTX *ctx);

int EVP_RAND_verify_zeroization(EVP_RAND_CTX *ctx);
unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx);
int EVP_RAND_get_state(EVP_RAND_CTX *ctx);

#ifdef  __cplusplus
}
#endif

#endif
