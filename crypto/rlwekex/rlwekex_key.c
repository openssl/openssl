/* crypto/rlwekex/rlwekex_key.c */

#include <string.h>
#include <openssl/rand.h>
#include "rlwekex_locl.h"

#define RANDOMNESS_AESCTR

#ifdef RANDOMNESS_AESCTR
#include <openssl/aes.h>
#define RANDOM_VARS \
	AES_KEY aes_key; \
	unsigned char aes_key_bytes[16]; \
	RAND_bytes(aes_key_bytes, 16); \
	AES_set_encrypt_key(aes_key_bytes, 128, &aes_key); \
	unsigned char aes_ivec[AES_BLOCK_SIZE]; \
	memset(aes_ivec, 0, AES_BLOCK_SIZE); \
	unsigned char aes_ecount_buf[AES_BLOCK_SIZE]; \
	memset(aes_ecount_buf, 0, AES_BLOCK_SIZE); \
	unsigned int aes_num = 0; \
	unsigned char aes_in[AES_BLOCK_SIZE]; \
	memset(aes_in, 0, AES_BLOCK_SIZE);
#define RANDOM8   ((uint8_t) randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))
#define RANDOM32 ((uint32_t) randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))
#define RANDOM64 ((uint64_t) randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in))

uint64_t randomplease(AES_KEY *aes_key, unsigned char aes_ivec[AES_BLOCK_SIZE],
                      unsigned char aes_ecount_buf[AES_BLOCK_SIZE],
                      unsigned int *aes_num, unsigned char aes_in[AES_BLOCK_SIZE]) {
	uint64_t out;
	AES_ctr128_encrypt(aes_in, (unsigned char *) &out, 8, aes_key, aes_ivec, aes_ecount_buf, aes_num);
	return out;
}
#endif

#ifdef RANDOMNESS_RCFOUR
#include <openssl/rc4.h>
#define RANDOM_VARS \
	RC4_KEY rc4_key; \
	unsigned char rc4_key_bytes[16]; \
	RAND_bytes(rc4_key_bytes, 16); \
	RC4_set_key(&rc4_key, 16, rc4_key_bytes);

#define RANDOM8   ((uint8_t) randomplease(&rc4_key))
#define RANDOM32 ((uint32_t) randomplease(&rc4_key))
#define RANDOM64 ((uint64_t) randomplease(&rc4_key))

uint64_t randomplease(RC4_KEY *rc4_key) {
	uint64_t b;
	uint64_t z = (uint64_t) 0;
	RC4(rc4_key, 8, (unsigned char *) &z, (unsigned char *) &b);
	return b;
}

#endif

#ifdef RANDOMNESS_RAND_bytes
#define RANDOM_VARS
#define RANDOM8 (random8())
#define RANDOM32 (random32())
#define RANDOM64 (random64())

uint8_t random8() {
	uint8_t b;
	int r = RAND_bytes((unsigned char *) &b, 1);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM8, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
uint32_t random32() {
	uint32_t b;
	int r = RAND_bytes((unsigned char *) &b, 4);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM32, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
uint64_t random64() {
	uint64_t b;
	int r = RAND_bytes((unsigned char *) &b, 8);
	if (r != 1) {
		RLWEKEXerr(RLWEKEX_F_RANDOM64, RLWEKEX_R_RANDOM_FAILED);
	}
	return b;
}
#endif

#include "rlwekexlib/fft.c"
#include "rlwekexlib/rlwe.c"
#include "rlwekexlib/rlwe_a.h"

/* Allocate and deallocate auxiliary variables (context) data structure */

RLWE_CTX *RLWE_CTX_new(void) {
	RLWE_CTX *ret;
	ret = (RLWE_CTX *)OPENSSL_malloc(sizeof(RLWE_CTX));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->fft_ctx = (FFT_CTX *)OPENSSL_malloc(sizeof(FFT_CTX));
	if (ret->fft_ctx == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	if (FFT_CTX_init(ret->fft_ctx) == 0) {
		goto err;
	}
	return (ret);
  err:
  	FFT_CTX_free(ret->fft_ctx);
  	OPENSSL_free(ret->fft_ctx);
  	OPENSSL_free(ret);
  	return (NULL);
}

void RLWE_CTX_free(RLWE_CTX *r) {
	if (r == NULL) return;
	FFT_CTX_clear(r->fft_ctx);
	FFT_CTX_free(r->fft_ctx);
	OPENSSL_free(r->fft_ctx);
	OPENSSL_cleanse((void *)r, sizeof(RLWE_CTX));
	OPENSSL_free(r);
}

/* Allocate and deallocate public parameters data structure */

RLWE_PARAM *RLWE_PARAM_new(void) {
	RLWE_PARAM *ret;

	ret = (RLWE_PARAM *)OPENSSL_malloc(sizeof(RLWE_PARAM));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PARAM_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->a = (uint32_t *) rlwe_a;

	return (ret);
}

void RLWE_PARAM_free(RLWE_PARAM *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("RLWE_PARAM", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "RLWE_PARAM_free, bad reference count\n");
		abort();
	}
#endif

	OPENSSL_cleanse((void *)r, sizeof(RLWE_PARAM));

	OPENSSL_free(r);
}

/* Allocate and deallocate public key data structure */

RLWE_PUB *RLWE_PUB_new(void) {
	RLWE_PUB *ret;

	ret = (RLWE_PUB *)OPENSSL_malloc(sizeof(RLWE_PUB));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PUB_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->param = NULL;
	ret->b = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));

	return (ret);
}

RLWE_PUB *RLWE_PUB_copy(RLWE_PUB *dest, const RLWE_PUB *src) {
	if (dest == NULL || src == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PUB_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* copy the parameters; this takes advantage of the fact that we only currently
	   support one set of parameters */
	if (!dest->param) {
		dest->param = RLWE_PARAM_new();
	}

	/* copy the public key */
	if (src->b) {
		if (!dest->b) {
			dest->b = OPENSSL_malloc(1024 * sizeof (uint32_t));
		}
		memcpy(dest->b, src->b, 1024 * sizeof (uint32_t));
	}

	/* copy the rest */
	dest->version   = src->version;
	dest->flags = src->flags;

	return dest;
}

void RLWE_PUB_free(RLWE_PUB *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("RLWE_PUB", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "RLWE_PUB_free, bad reference count\n");
		abort();
	}
#endif

	RLWE_PARAM_free(r->param);

	OPENSSL_cleanse(r->b, 1024 * sizeof (uint32_t));
	OPENSSL_free(r->b);

	OPENSSL_cleanse((void *)r, sizeof(RLWE_PUB));

	OPENSSL_free(r);
}

/* Allocate and deallocate public key / private key pair data structure */

RLWE_PAIR *RLWE_PAIR_new(void) {
	RLWE_PAIR *ret;

	ret = (RLWE_PAIR *)OPENSSL_malloc(sizeof(RLWE_PAIR));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->pub = NULL;

	ret->s = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));
	ret->e = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));

	return (ret);
}

RLWE_PAIR *RLWE_PAIR_copy(RLWE_PAIR *dest, const RLWE_PAIR *src) {
	if (dest == NULL || src == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_PAIR_COPY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	/* copy the public key */
	if (src->pub) {
		if (dest->pub)
			RLWE_PUB_free(dest->pub);
		dest->pub = RLWE_PUB_new();
		if (dest->pub == NULL)
			return NULL;
		if (!RLWE_PUB_copy(dest->pub, src->pub))
			return NULL;
	}

	/* copy the private key */
	if (src->s) {
		if (!dest->s) {
			dest->s = OPENSSL_malloc(1024 * sizeof (uint32_t));
		}
		memcpy(dest->s, src->s, 1024 * sizeof (uint32_t));
	}
	if (src->e) {
		if (!dest->e) {
			dest->e = OPENSSL_malloc(1024 * sizeof (uint32_t));
		}
		memcpy(dest->e, src->e, 1024 * sizeof (uint32_t));
	}

	/* copy the rest */
	dest->version   = src->version;
	dest->flags = src->flags;

	return dest;
}

RLWE_PAIR *RLWE_PAIR_dup(const RLWE_PAIR *pair) {
	RLWE_PAIR *ret = RLWE_PAIR_new();
	if (ret == NULL)
		return NULL;
	if (RLWE_PAIR_copy(ret, pair) == NULL) {
		RLWE_PAIR_free(ret);
		return NULL;
	}
	return ret;
}

void RLWE_PAIR_free(RLWE_PAIR *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("RLWE_PAIR", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "RLWE_PAIR_free, bad reference count\n");
		abort();
	}
#endif

	RLWE_PUB_free(r->pub);

	OPENSSL_cleanse(r->s, 1024 * sizeof (uint32_t));
	OPENSSL_free(r->s);
	OPENSSL_cleanse(r->e, 1024 * sizeof (uint32_t));
	OPENSSL_free(r->e);

	OPENSSL_cleanse((void *)r, sizeof(RLWE_PAIR));

	OPENSSL_free(r);
}

/* Allocate and deallocate reconciliation data structure */

RLWE_REC *RLWE_REC_new(void) {
	RLWE_REC *ret;

	ret = (RLWE_REC *)OPENSSL_malloc(sizeof(RLWE_REC));
	if (ret == NULL) {
		RLWEKEXerr(RLWEKEX_F_RLWE_REC_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->version = 1;
	ret->flags = 0;
	ret->references = 1;

	ret->c = (uint64_t *) malloc (16 * sizeof (uint64_t));

	return (ret);
}

void RLWE_REC_free(RLWE_REC *r) {
	int i;

	if (r == NULL) return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("RLWE_REC", r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0) {
		fprintf(stderr, "RLWE_REC_free, bad reference count\n");
		abort();
	}
#endif

	OPENSSL_cleanse(r->c, 16 * sizeof (uint64_t));
	OPENSSL_free(r->c);

	OPENSSL_cleanse((void *)r, sizeof(RLWE_REC));

	OPENSSL_free(r);
}

/* Generate key pair */

int RLWE_PAIR_generate_key(RLWE_PAIR *key, RLWE_CTX *ctx) {
	int	ok = 0;

	key->pub = RLWE_PUB_new();
	if (key->pub == NULL) {
		goto err;
	}

	key->pub->param = RLWE_PARAM_new();
	if (key->pub->param == NULL) {
		goto err;
	}

#if CONSTANT_TIME
	sample_ct(key->s);
	sample_ct(key->e);
#else
	sample(key->s);
	sample(key->e);
#endif
	key_gen(key->pub->b, key->pub->param->a, key->s, key->e, ctx->fft_ctx);

	ok = 1;
	goto err;

err:
	return (ok);
}

/* Convert public keys data structures from/to binary */

RLWE_PUB *o2i_RLWE_PUB(RLWE_PUB **pub, const unsigned char *in, long len) {
	int i;
	if (pub == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (*pub == NULL && (*pub = RLWE_PUB_new()) == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (len != 1024 * 4) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_PUB, RLWEKEX_R_INVALID_LENGTH);
		return 0;
	}

	for (i = 0; i < 1024; i++) {
		(*pub)->b[i] = (((uint32_t) in[4 * i + 0]) << 24) |
		               (((uint32_t) in[4 * i + 1]) << 16) |
		               (((uint32_t) in[4 * i + 2]) << 8) |
		               ( (uint32_t) in[4 * i + 3]);
	}

	return *pub;
}

int i2o_RLWE_PUB(RLWE_PUB *pub, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0, i;

	if (pub == NULL) {
		RLWEKEXerr(RLWEKEX_F_I2O_RLWE_PUB, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	buf_len = 1024 * 4;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
		return buf_len;

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			RLWEKEXerr(RLWEKEX_F_I2O_RLWE_PUB, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	for (i = 0; i < 1024; i++) {
		(*out)[4 * i + 0] = (unsigned char)  (pub->b[i] >> 24);
		(*out)[4 * i + 1] = (unsigned char) ((pub->b[i] >> 16) & 0xff);
		(*out)[4 * i + 2] = (unsigned char) ((pub->b[i] >>  8) & 0xff);
		(*out)[4 * i + 3] = (unsigned char) ( pub->b[i]        & 0xff);
	}

	if (!new_buffer)
		*out += buf_len;
	return buf_len;
}

/* Convert reconciliation data structure from/to binary */

RLWE_REC *o2i_RLWE_REC(RLWE_REC **rec, const unsigned char *in, long len) {

	if (rec == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (*rec == NULL && (*rec = RLWE_REC_new()) == NULL) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (len != 16 * 8) {
		RLWEKEXerr(RLWEKEX_F_O2I_RLWE_REC, RLWEKEX_R_INVALID_LENGTH);
		return 0;
	}

	memcpy((unsigned char *) ((*rec)->c), in, len);

	return *rec;
}

int i2o_RLWE_REC(RLWE_REC *rec, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0;

	if (rec == NULL) {
		RLWEKEXerr(RLWEKEX_F_I2O_RLWE_REC, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	buf_len = 16 * 8;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
		return buf_len;

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			RLWEKEXerr(RLWEKEX_F_I2O_RLWE_REC, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		new_buffer = 1;
	}

	memcpy(*out, (unsigned char *) rec->c, buf_len);

	if (!new_buffer)
		*out += buf_len;
	return buf_len;
}

/* Get public key from a key pair */
RLWE_PUB *RLWE_PAIR_get_publickey(RLWE_PAIR *pair) {
	if (pair == NULL) return NULL;
	return pair->pub;
}

/* Does private key exist? */
int RLWE_PAIR_has_privatekey(RLWE_PAIR *pair) {
	return (pair->s != NULL) && (pair->e != NULL);
}

/* Compute shared secret values */
int RLWEKEX_compute_key_alice(void *out, size_t outlen, const RLWE_PUB *peer_pub_key,  const RLWE_REC *peer_reconciliation,
                              const RLWE_PAIR *priv_pub_key, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), RLWE_CTX *ctx) {

	int ret = -1;

	uint32_t *w = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));
	uint64_t *ka  = (uint64_t *) OPENSSL_malloc (16 * sizeof (uint64_t));

	FFT_mul(w, peer_pub_key->b, priv_pub_key->s, ctx->fft_ctx);
#if CONSTANT_TIME
	rec_ct (ka, w, peer_reconciliation->c);
#else
	rec (ka, w, peer_reconciliation->c);
#endif

	if (KDF != 0) {
		if (KDF((unsigned char *) ka, 16 * sizeof(uint64_t), out, &outlen) == NULL) {
			RLWEKEXerr(RLWEKEX_F_RLWEKEX_COMPUTE_KEY_ALICE, RLWEKEX_R_KDF_FAILED);
			goto err;
		}
		ret = outlen;
	} else {
		/* no KDF, just copy as much as we can */
		if (outlen > 16 * sizeof(uint64_t))
			outlen = 16 * sizeof(uint64_t);
		memcpy(out, (unsigned char *) ka, outlen);
		ret = outlen;
	}

err:
	if (w) OPENSSL_free(w);
	if (ka) OPENSSL_free(ka);
	return (ret);

}

int RLWEKEX_compute_key_bob(void *out, size_t outlen, RLWE_REC *reconciliation, const RLWE_PUB *peer_pub_key,  const RLWE_PAIR *priv_pub_key,
                            void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen), RLWE_CTX *ctx) {

	int ret = -1;

	uint32_t *v  = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));
	uint64_t *kb = (uint64_t *) OPENSSL_malloc (16 * sizeof (uint64_t));

	uint32_t *eprimeprime = (uint32_t *) OPENSSL_malloc (1024 * sizeof (uint32_t));
#if CONSTANT_TIME
	sample_ct(eprimeprime);
#else
	sample(eprimeprime);
#endif
	key_gen(v, peer_pub_key->b, priv_pub_key->s, eprimeprime, ctx->fft_ctx);
	OPENSSL_free(eprimeprime);

#if CONSTANT_TIME
	crossround2_ct(reconciliation->c, v);
	round2_ct(kb, v);
#else
	crossround2(reconciliation->c, v);
	round2(kb, v);
#endif

	if (KDF != 0) {
		if (KDF((unsigned char *) kb, 16 * sizeof(uint64_t), out, &outlen) == NULL) {
			RLWEKEXerr(RLWEKEX_F_RLWEKEX_COMPUTE_KEY_BOB, RLWEKEX_R_KDF_FAILED);
			goto err;
		}
		ret = outlen;
	} else {
		/* no KDF, just copy as much as we can */
		if (outlen > 16 * sizeof(uint64_t))
			outlen = 16 * sizeof(uint64_t);
		memcpy(out, (unsigned char *) kb, outlen);
		ret = outlen;
	}

err:
	if (v) OPENSSL_free(v);
	if (kb) OPENSSL_free(kb);
	return (ret);

}
