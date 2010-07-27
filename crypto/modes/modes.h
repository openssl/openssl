/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project. All rights reserved.
 *
 * Rights for redistribution and usage in source and binary
 * forms are granted according to the OpenSSL license.
 */

#include <stddef.h>

typedef void (*block128_f)(const unsigned char in[16],
			unsigned char out[16],
			const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16]);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, block128_f block);

void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, ctr128_f ctr);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			block128_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
			size_t bits, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);

size_t CRYPTO_cts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);

size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);

typedef struct gcm128_context GCM128_CONTEXT;

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
			size_t len);
void CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
			size_t len);
void CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
void CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int  CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx,const unsigned char *tag,
			size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);
