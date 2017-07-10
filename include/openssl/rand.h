/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RAND_H
# define HEADER_RAND_H

# include <stdlib.h>
# include <openssl/ossl_typ.h>
# include <openssl/e_os2.h>
# include <openssl/randerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};

# ifdef BN_DEBUG
extern int rand_predictable;
# endif

int RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD *RAND_get_rand_method(void);
# ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine);
# endif
RAND_METHOD *RAND_OpenSSL(void);
#if OPENSSL_API_COMPAT < 0x10100000L
# define RAND_cleanup() while(0) continue
#endif
int RAND_bytes(unsigned char *buf, int num);
DEPRECATEDIN_1_1_0(int RAND_pseudo_bytes(unsigned char *buf, int num))
void RAND_seed(const void *buf, int num);
#if defined(__ANDROID__) && defined(__NDK_FPABI__)
__NDK_FPABI__	/* __attribute__((pcs("aapcs"))) on ARM */
#endif
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

#if defined(_WIN32) && (defined(BASETYPES) || defined(_WINDEF_H))
/* application has to include <windows.h> in order to use these */
DEPRECATEDIN_1_1_0(void RAND_screen(void))
DEPRECATEDIN_1_1_0(int RAND_event(UINT, WPARAM, LPARAM))
#endif

int ERR_load_RAND_strings(void);

/* Flag for CTR mode only: use derivation function ctr_df */
#define RAND_DRBG_FLAG_CTR_USE_DF            0x1

const RAND_METHOD *RAND_drbg(void);

int RAND_DRBG_set(DRBG_CTX *ctx, int type, unsigned int flags);
DRBG_CTX *RAND_DRBG_new(int type, unsigned int flags);
int RAND_DRBG_instantiate(DRBG_CTX *dctx,
                          const unsigned char *pers, size_t perslen);
int RAND_DRBG_uninstantiate(DRBG_CTX *dctx);
int RAND_DRBG_reseed(DRBG_CTX *dctx, const unsigned char *adin, size_t adinlen);
int RAND_DRBG_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen);
void RAND_DRBG_free(DRBG_CTX *dctx);

int RAND_DRBG_set_callbacks(DRBG_CTX *dctx,
    size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len),
    void (*cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
    size_t entropy_blocklen,
    size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len),
    void (*cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen)
    );

int RAND_DRBG_set_rand_callbacks(DRBG_CTX *dctx,
    size_t (*get_adin)(DRBG_CTX *ctx, unsigned char **pout),
    void (*cleanup_adin)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
    int (*rand_seed_cb)(DRBG_CTX *ctx, const void *buf, int num),
    int (*rand_add_cb)(DRBG_CTX *ctx,
                       const void *buf, int num, double entropy)
    );
void RAND_DRBG_set_check_interval(DRBG_CTX *dctx, int interval);
void RAND_DRBG_set_reseed_interval(DRBG_CTX *dctx, int interval);

void *RAND_DRBG_get_app_data(const DRBG_CTX *ctx);
void RAND_DRBG_set_app_data(DRBG_CTX *ctx, void *app_data);
size_t RAND_DRBG_get_blocklength(const DRBG_CTX *dctx);
int RAND_DRBG_get_strength(const DRBG_CTX *dctx);

DRBG_CTX *RAND_DRBG_get_default(void);

#ifdef  __cplusplus
}
#endif

#endif
