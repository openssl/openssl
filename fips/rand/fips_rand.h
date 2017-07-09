/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef HEADER_FIPS_RAND_H
#define HEADER_FIPS_RAND_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>

#ifdef OPENSSL_FIPS

#ifdef  __cplusplus
extern "C" {
#endif

int FIPS_x931_set_key(const unsigned char *key, int keylen);
int FIPS_x931_seed(const void *buf, int num);
int FIPS_x931_bytes(unsigned char *out, int outlen);

int FIPS_x931_test_mode(void);
void FIPS_x931_reset(void);
int FIPS_x931_set_dt(unsigned char *dt);

int FIPS_x931_status(void);

const RAND_METHOD *FIPS_x931_method(void);

typedef struct drbg_ctx_st DRBG_CTX;
/* DRBG external flags */
/* Flag for CTR mode only: use derivation function ctr_df */
#define	DRBG_FLAG_CTR_USE_DF		0x1
/* PRNG is in test state */
#define	DRBG_FLAG_TEST			0x2

DRBG_CTX *FIPS_drbg_new(int type, unsigned int flags);
int FIPS_drbg_init(DRBG_CTX *dctx, int type, unsigned int flags);
int FIPS_drbg_instantiate(DRBG_CTX *dctx,
				const unsigned char *pers, size_t perslen);
int FIPS_drbg_reseed(DRBG_CTX *dctx, const unsigned char *adin, size_t adinlen);
int FIPS_drbg_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
			int prediction_resistance,
			const unsigned char *adin, size_t adinlen);

int FIPS_drbg_uninstantiate(DRBG_CTX *dctx);
void FIPS_drbg_free(DRBG_CTX *dctx);

int FIPS_drbg_set_callbacks(DRBG_CTX *dctx,
	size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len),
	void (*cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
	size_t entropy_blocklen,
	size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len),
	void (*cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen));

int FIPS_drbg_set_rand_callbacks(DRBG_CTX *dctx,
	size_t (*get_adin)(DRBG_CTX *ctx, unsigned char **pout),
	void (*cleanup_adin)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
	int (*rand_seed_cb)(DRBG_CTX *ctx, const void *buf, int num),
	int (*rand_add_cb)(DRBG_CTX *ctx,
				const void *buf, int num, double entropy));

void *FIPS_drbg_get_app_data(DRBG_CTX *ctx);
void FIPS_drbg_set_app_data(DRBG_CTX *ctx, void *app_data);
size_t FIPS_drbg_get_blocklength(DRBG_CTX *dctx);
int FIPS_drbg_get_strength(DRBG_CTX *dctx);
void FIPS_drbg_set_check_interval(DRBG_CTX *dctx, int interval);
void FIPS_drbg_set_reseed_interval(DRBG_CTX *dctx, int interval);

int FIPS_drbg_health_check(DRBG_CTX *dctx);

DRBG_CTX *FIPS_get_default_drbg(void);
const RAND_METHOD *FIPS_drbg_method(void);


int FIPS_rand_set_method(const RAND_METHOD *meth);
const RAND_METHOD *FIPS_rand_get_method(void);

void FIPS_rand_set_bits(int nbits);

int FIPS_rand_strength(void);

#ifdef  __cplusplus
}
#endif
#endif
#endif
