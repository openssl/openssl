#ifndef GOSTKEYX_H
#define GOSTKEYX_H
/**********************************************************************
 *                             gostkeyx.h                            *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *	Declaration of the key transport functions for GOST pkey methods  *
 *																	  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <openssl/evp.h>
#include "gost89.h"
/* EVP_PKEY_METHOD callbacks */
/* From gost94_keyx.c */
int pkey_GOST94cp_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char* key, size_t key_len );
int pkey_GOST94cc_encrypt (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,  const unsigned char *   key,size_t key_len);

int pkey_GOST94cp_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char* in, size_t in_len );
int pkey_GOST94cc_decrypt (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,  const unsigned char *   in,size_t in_len);
/* From gost2001_keyx.c */
int pkey_GOST01cp_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char* key, size_t key_len );
int pkey_GOST01cc_encrypt (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,  const unsigned char *   key,size_t key_len);

int pkey_GOST01cp_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char* in, size_t in_len );
int pkey_GOST01cc_decrypt (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *   in,size_t in_len);

/* Internal functions to make error processing happy */
int decrypt_cryptocom_key(unsigned char *sess_key,int max_key_len,
		const unsigned char *crypted_key,int crypted_key_len, gost_ctx *ctx);
int encrypt_cryptocom_key(const unsigned char *sess_key,int key_len,
		unsigned char *crypted_key, gost_ctx *ctx);
/*int compute_pair_key_le(unsigned char *pair_key,BIGNUM *pub_key,DH *dh) ;*/
/*
 * Computes 256 bit key exchange key for CryptoCom variation of GOST 94
 * algorithm
 *//*
int make_gost_shared_key(DH *dh,EVP_PKEY *pubk,unsigned char *shared_key) ;
DH *make_ephemeral_key(EVP_PKEY *pubk,BIGNUM *ephemeral_key);
int make_cp_exchange_key(DH *dh,EVP_PKEY *pubk, unsigned char *shared_key);
*/
#endif
