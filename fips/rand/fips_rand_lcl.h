/* fips/rand/fips_rand_lcl.h */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 */

typedef struct drbg_hash_ctx_st DRBG_HASH_CTX;
typedef struct drbg_hmac_ctx_st DRBG_HMAC_CTX;
typedef struct drbg_ctr_ctx_st DRBG_CTR_CTX;
typedef struct drbg_ec_ctx_st DRBG_EC_CTX;

/* 888 bits from 10.1 table 2 */
#define HASH_PRNG_MAX_SEEDLEN	111

struct drbg_hash_ctx_st
	{
	const EVP_MD *md;
	EVP_MD_CTX mctx;
	unsigned char V[HASH_PRNG_MAX_SEEDLEN];
	unsigned char C[HASH_PRNG_MAX_SEEDLEN];
	/* Temporary value storage: should always exceed max digest length */
	unsigned char vtmp[HASH_PRNG_MAX_SEEDLEN];
	};

struct drbg_hmac_ctx_st
	{
	const EVP_MD *md;
	HMAC_CTX hctx;
	unsigned char K[EVP_MAX_MD_SIZE];
	unsigned char V[EVP_MAX_MD_SIZE];
	};

struct drbg_ctr_ctx_st
	{
	AES_KEY ks;
	size_t keylen;
	unsigned char K[32];
	unsigned char V[16];
	/* Temp variables used by derivation function */
	AES_KEY df_ks;
	AES_KEY df_kxks;
	/* Temporary block storage used by ctr_df */
	unsigned char bltmp[16];
	size_t bltmp_pos;
	unsigned char KX[48];
	};

/* Maximum seed length */
#define EC_PRNG_MAX_SEEDLEN	66

struct drbg_ec_ctx_st
	{
	/* Message digest to use */
	const EVP_MD *md;
	/* Curve to use: generator is point P */
	EC_GROUP *curve;
	/* Point Q */
	EC_POINT *Q;
	/* Temporary point */
	EC_POINT *ptmp;
	size_t exbits;
	/* Secret s value */
	BIGNUM *s;
	/* Buffer to store byte version of s value */
	unsigned char sbuf[EC_PRNG_MAX_SEEDLEN];
	/* Buffer to store byte version of t value */
	unsigned char tbuf[EC_PRNG_MAX_SEEDLEN];
	/* Digest context */
	EVP_MD_CTX mctx;
	/* Temporary value storage: should always exceed max digest length */
	unsigned char vtmp[EC_PRNG_MAX_SEEDLEN];
	/* Temp BN context */
	BN_CTX *bctx;
	};

/* DRBG internal flags */

/* Functions shouldn't call err library */
#define	DRBG_FLAG_NOERR			0x1
/* Custom reseed checking */
#define	DRBG_CUSTOM_RESEED		0x2

/* DRBG status values */
/* not initialised */
#define DRBG_STATUS_UNINITIALISED	0
/* ok and ready to generate random bits */
#define DRBG_STATUS_READY		1
/* reseed required */
#define DRBG_STATUS_RESEED		2
/* fatal error condition */
#define DRBG_STATUS_ERROR		3

/* A default maximum length: larger than any reasonable value used in pratice */

#define DRBG_MAX_LENGTH			0x7ffffff0
/* Maximum DRBG block length: all md sizes are bigger than cipher blocks sizes
 * so use max digest length.
 */
#define DRBG_MAX_BLOCK			EVP_MAX_MD_SIZE

#define DRBG_HEALTH_INTERVAL		(1 << 24)

/* DRBG context structure */

struct drbg_ctx_st
	{
	/* First types common to all implementations */
	/* DRBG type: a NID for the underlying algorithm */
	int type;
	/* Various external flags */
	unsigned int xflags;
	/* Various internal use only flags */
	unsigned int iflags;
	/* Used for periodic health checks */
	int health_check_cnt, health_check_interval;

	/* The following parameters are setup by mechanism drbg_init() call */
	int strength;
	size_t blocklength;
	size_t max_request;

	size_t min_entropy, max_entropy;
	size_t min_nonce, max_nonce;
	size_t max_pers, max_adin;
	unsigned int reseed_counter;
	unsigned int reseed_interval;
	size_t seedlen;
	int status;
	/* Application data: typically used by test get_entropy */
	void *app_data;
	/* Implementation specific structures */
	union 
		{
		DRBG_HASH_CTX hash;
		DRBG_HMAC_CTX hmac;
		DRBG_CTR_CTX  ctr;
		DRBG_EC_CTX  ec;
		} d;
	/* Initialiase PRNG and setup callbacks below */
	int (*init)(DRBG_CTX *ctx, int nid, int security, unsigned int flags);
	/* Intantiate PRNG */
	int (*instantiate)(DRBG_CTX *ctx,
				const unsigned char *ent, size_t entlen,
				const unsigned char *nonce, size_t noncelen,
				const unsigned char *pers, size_t perslen);
	/* reseed */
	int (*reseed)(DRBG_CTX *ctx,
				const unsigned char *ent, size_t entlen,
				const unsigned char *adin, size_t adinlen);
	/* generat output */
	int (*generate)(DRBG_CTX *ctx,
				unsigned char *out, size_t outlen,
				const unsigned char *adin, size_t adinlen);
	/* uninstantiate */
	int (*uninstantiate)(DRBG_CTX *ctx);

	/* Entropy source block length */
	size_t entropy_blocklen;

	/* entropy gathering function */
	size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len);
	/* Indicates we have finished with entropy buffer */
	void (*cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen);

	/* nonce gathering function */
	size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
				int entropy, size_t min_len, size_t max_len);
	/* Indicates we have finished with nonce buffer */
	void (*cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen);

	/* Continuous random number test temporary area */
	/* Last block */	
	unsigned char lb[EVP_MAX_MD_SIZE];
	/* set if lb is valid */
	int lb_valid;

	/* Callbacks used when called through RAND interface */
	/* Get any additional input for generate */
	size_t (*get_adin)(DRBG_CTX *ctx, unsigned char **pout);
	void (*cleanup_adin)(DRBG_CTX *ctx, unsigned char *out, size_t olen);
	/* Callback for RAND_seed(), RAND_add() */
	int (*rand_seed_cb)(DRBG_CTX *ctx, const void *buf, int num);
	int (*rand_add_cb)(DRBG_CTX *ctx,
				const void *buf, int num, double entropy);
	};


int fips_drbg_ctr_init(DRBG_CTX *dctx);
int fips_drbg_hash_init(DRBG_CTX *dctx);
int fips_drbg_hmac_init(DRBG_CTX *dctx);
int fips_drbg_ec_init(DRBG_CTX *dctx);
int fips_drbg_kat(DRBG_CTX *dctx, int nid, unsigned int flags);
int fips_drbg_cprng_test(DRBG_CTX *dctx, const unsigned char *out);
