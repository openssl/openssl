/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/aes_siv.h>
#include "internal/evp_int.h"

typedef union block_un {
    uint64_t word[2];
    unsigned char byte[16];
} block;

struct aes_siv_ctx_st {
    /*
     * |d| stores intermediate results of S2V; it corresponds to
     * D from the pseudocode in section 2.4 of RFC 5297.
     */
    block d;
    EVP_CIPHER_CTX *cipher_ctx;
    /*
     * SIV_AES_Init() sets up |cmac_ctx_init|. |cmac_ctx| is a scratchpad
     * used by SIV_AES_AssociateData() and SIV_AES_(En|De)cryptFinal.
     */
    CMAC_CTX *cmac_ctx_init;
    CMAC_CTX *cmac_ctx;
};

static ossl_inline uint64_t getword(block const *block, size_t i)
{
    i <<= 3;
    return ((uint64_t)block->byte[i + 7])
	 | ((uint64_t)block->byte[i + 6] <<  8)
	 | ((uint64_t)block->byte[i + 5] << 16)
	 | ((uint64_t)block->byte[i + 4] << 24)
	 | ((uint64_t)block->byte[i + 3] << 32)
	 | ((uint64_t)block->byte[i + 2] << 40)
	 | ((uint64_t)block->byte[i + 1] << 48)
	 | ((uint64_t)block->byte[i    ] << 56);
}

static ossl_inline void putword(block *block, size_t i, uint64_t x)
{
    i <<= 3;
    block->byte[i    ] = (unsigned char)((x >> 56) & 0xff);
    block->byte[i + 1] = (unsigned char)((x >> 48) & 0xff);
    block->byte[i + 2] = (unsigned char)((x >> 40) & 0xff);
    block->byte[i + 3] = (unsigned char)((x >> 32) & 0xff);
    block->byte[i + 4] = (unsigned char)((x >> 24) & 0xff);
    block->byte[i + 5] = (unsigned char)((x >> 16) & 0xff);
    block->byte[i + 6] = (unsigned char)((x >>  8) & 0xff);
    block->byte[i + 7] = (unsigned char)((x      ) & 0xff);
}

static ossl_inline void xorblock(block *x, block const *y)
{
    x->word[0] ^= y->word[0];
    x->word[1] ^= y->word[1];
}

/*
 * Doubles `block`, which is 16 bytes representing an element of
 * GF(2**128) modulo the irreducible polynomial
 * x**128 + x**7 + x**2 + x + 1.
 */
static ossl_inline void dbl(block *block)
{
    uint64_t high = getword(block, 0);
    uint64_t low = getword(block, 1);
    uint64_t high_carry = high & (((uint64_t) 1) << 63);
    uint64_t low_carry = low & (((uint64_t) 1) << 63);
    int64_t low_mask = -((int64_t) (high_carry >> 63)) & 0x87;
    uint64_t high_mask = low_carry >> 63;

    high = (high << 1) | high_mask;
    low = (low << 1) ^ (uint64_t)low_mask;
    putword(block, 0, high);
    putword(block, 1, low);
}


void AES_SIV_CTX_free(AES_SIV_CTX *ctx)
{
    if (ctx == NULL)
	return;
    if (ctx->cipher_ctx != NULL) {
        EVP_CIPHER_CTX_cleanup(ctx->cipher_ctx);
        EVP_CIPHER_CTX_free(ctx->cipher_ctx);
    }
    if (ctx->cmac_ctx_init != NULL) {
        CMAC_CTX_cleanup(ctx->cmac_ctx_init);
        CMAC_CTX_free(ctx->cmac_ctx_init);
    }
    if (ctx->cmac_ctx != NULL) {
        CMAC_CTX_cleanup(ctx->cmac_ctx);
        CMAC_CTX_free(ctx->cmac_ctx);
    }
    OPENSSL_cleanse(&ctx->d, sizeof(ctx->d));
    OPENSSL_free(ctx);
}

AES_SIV_CTX *AES_SIV_CTX_new(void)
{
    AES_SIV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
	return NULL;

    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    ctx->cmac_ctx_init = CMAC_CTX_new();
    ctx->cmac_ctx = CMAC_CTX_new();
    if (ctx->cipher_ctx == NULL
	    || ctx->cmac_ctx_init == NULL
	    || ctx->cmac_ctx == NULL) {
	AES_SIV_CTX_free(ctx);
	return NULL;
    }

    return ctx;
}

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len)
{
    static const unsigned char zero[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0
    };
    size_t out_len;
    int ret = 0;

    switch (key_len) {
    case 32:
	if (CMAC_Init(ctx->cmac_ctx_init, key, 16,
		      EVP_aes_128_cbc(), NULL) != 1)
		    goto done;
	if (EVP_EncryptInit_ex(ctx->cipher_ctx, EVP_aes_128_ctr(),
			       NULL, key + 16, NULL) != 1)
	    goto done;
	break;
    case 48:
	if (CMAC_Init(ctx->cmac_ctx_init, key, 24,
		      EVP_aes_192_cbc(), NULL) != 1)
	    goto done;
	if (EVP_EncryptInit_ex(ctx->cipher_ctx, EVP_aes_192_ctr(),
			       NULL, key + 24, NULL) != 1)
	    goto done;
	break;
    case 64:
	if (CMAC_Init(ctx->cmac_ctx_init, key, 32,
		      EVP_aes_256_cbc(), NULL) != 1)
	    goto done;
	if (EVP_EncryptInit_ex(ctx->cipher_ctx, EVP_aes_256_ctr(),
		               NULL, key + 32, NULL) != 1)
	    goto done;
	break;
    default:
	    goto done;
    }

    if (CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)
	goto done;
    if (CMAC_Update(ctx->cmac_ctx, zero, sizeof(zero)) != 1)
	goto done;
    out_len = sizeof(ctx->d);
    if (CMAC_Final(ctx->cmac_ctx, ctx->d.byte, &out_len) != 1)
	goto done;
    ret = 1;

done:
    return ret;
}

int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
		      size_t len)
{
    block cmac_out;
    size_t out_len = sizeof(cmac_out);
    int ret = 0;

    dbl(&ctx->d);

    if (CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)
	goto done;
    if (CMAC_Update(ctx->cmac_ctx, data, len) != 1)
	goto done;
    if (CMAC_Final(ctx->cmac_ctx, cmac_out.byte, &out_len) != 1)
	goto done;

    xorblock(&ctx->d, &cmac_out);
    ret = 1;

done:
    return ret;
}

static ossl_inline int do_s2v_p(AES_SIV_CTX *ctx, block *out,
			        unsigned char const *in, size_t len)
{
    block t;
    size_t i, out_len = sizeof(out->byte);

    if (CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)
	return 0;

    if (len >= 16) {
        if (CMAC_Update(ctx->cmac_ctx, in, len - 16) != 1)
            return 0;
        memcpy(&t, in + (len - 16), 16);
        xorblock(&t, &ctx->d);
        if (CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)
            return 0;
    } else {
	memcpy(&t, in, len);
	t.byte[len] = 0x80;
	for (i = len + 1; i < 16; i++)
	    t.byte[i] = 0;
	dbl(&ctx->d);
	xorblock(&t, &ctx->d);
	if (CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)
	    return 0;
    }
    if (CMAC_Final(ctx->cmac_ctx, out->byte, &out_len) != 1)
	return 0;
    return 1;
}

static ossl_inline int do_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
			          unsigned char const *in,
                                  size_t len, block *icv)
{
    const int chunk_size = 1 << 30;
    size_t len_remaining = len;
    int out_len;
    int ret;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, icv->byte) != 1)
	return 0;

    while (len_remaining > (size_t)chunk_size) {
	out_len = chunk_size;
	if (EVP_EncryptUpdate(ctx, out, &out_len, in, out_len) != 1)
	    return 0;
	out += out_len;
	in += out_len;
	len_remaining -= (size_t)out_len;
    }

    out_len = (int)len_remaining;
    ret = EVP_EncryptUpdate(ctx, out, &out_len, in, out_len);
    return ret;
}

int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
			 unsigned char *c_out,
			 unsigned char const *plaintext, size_t len)
{
    block q;
    int ret = 0;

    if (do_s2v_p(ctx, &q, plaintext, len) != 1)
	goto done;

    memcpy(v_out, &q, 16);
    q.byte[8] &= 0x7f;
    q.byte[12] &= 0x7f;

    if (do_encrypt(ctx->cipher_ctx, c_out, plaintext, len, &q) != 1)
	goto done;

    ret = 1;

done:
    return ret;
}

int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
		     unsigned char const *v, unsigned char const *c,
		     size_t len)
{
    block t, q;
    size_t i;
    uint64_t result;
    int ret = 0;

    memcpy(&q, v, 16);
    q.byte[8] &= 0x7f;
    q.byte[12] &= 0x7f;

    if (do_encrypt(ctx->cipher_ctx, out, c, len, &q) != 1)
	goto done;
    if (do_s2v_p(ctx, &t, out, len) != 1)
	goto done;

    for (i = 0; i < 16; i++)
	t.byte[i] ^= v[i];

    result = t.word[0] | t.word[1];
    ret = !result;
    if (ret == 0)
	OPENSSL_cleanse(out, len);

done:
    return ret;
}

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
		unsigned char const *key, size_t key_len,
		unsigned char const *nonce, size_t nonce_len,
		unsigned char const *plaintext, size_t plaintext_len,
		unsigned char const *ad, size_t ad_len)
{
    if (*out_len < plaintext_len + 16)
	return 0;
    *out_len = plaintext_len + 16;

    if (AES_SIV_Init(ctx, key, key_len) != 1)
	return 0;
    if (AES_SIV_AssociateData(ctx, ad, ad_len) != 1)
	return 0;
    if (nonce != NULL && AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)
	return 0;
    if (AES_SIV_EncryptFinal(ctx, out, out + 16, plaintext,
		plaintext_len) != 1)
	return 0;

    return 1;
}

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
		unsigned char const *key, size_t key_len,
		unsigned char const *nonce, size_t nonce_len,
		unsigned char const *ciphertext, size_t ciphertext_len,
		unsigned char const *ad, size_t ad_len)
{
    if (ciphertext_len < 16)
	return 0;
    if (*out_len < ciphertext_len - 16)
	return 0;
    *out_len = ciphertext_len - 16;

    if (AES_SIV_Init(ctx, key, key_len) != 1)
	return 0;
    if (AES_SIV_AssociateData(ctx, ad, ad_len) != 1)
	return 0;
    if (nonce != NULL && AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)
	return 0;
    if (AES_SIV_DecryptFinal(ctx, out, ciphertext, ciphertext + 16,
		ciphertext_len - 16) != 1)
	return 0;
    return 1;
}

static EVP_CIPHER aes_siv_128_cipher = {
    0
};
static EVP_CIPHER aes_siv_192_cipher = {
    0
};
static EVP_CIPHER aes_siv_256_cipher = {
    0
};

const EVP_CIPHER *EVP_aes_128_siv(void)
{
    return &aes_siv_128_cipher;
}

const EVP_CIPHER *EVP_aes_192_siv(void)
{
    return &aes_siv_192_cipher;
}

const EVP_CIPHER *EVP_aes_256_siv(void)
{
    return &aes_siv_256_cipher;
}
