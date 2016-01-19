/*
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.
 * You may use this under the terms of the CC0, the OpenSSL Licence, or the
 * Apache Public License 2.0, at your option.  The terms of these licenses can
 * be found at:
 *
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 * - CC0 1.0 Universal : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 * 
 */

/* crypto/blake2/blake2.h */

#ifndef HEADER_BLAKE2_H
# define HEADER_BLAKE2_H

#ifdef  __cplusplus
extern "C" {
#endif

# ifdef OPENSSL_NO_BLAKE2
#  error BLAKE2 is disabled.
# endif

#define BLAKE2B_DIGEST_LENGTH 64
#define BLAKE2S_DIGEST_LENGTH 32

typedef struct blake2s_ctx_st BLAKE2S_CTX;
typedef struct blake2b_ctx_st BLAKE2B_CTX;

int BLAKE2b_Init(BLAKE2B_CTX *c);
int BLAKE2b_InitKey(BLAKE2B_CTX *c, const void *key, size_t keylen);
int BLAKE2b_Update(BLAKE2B_CTX *c, const void *data, size_t datalen);
int BLAKE2b_Final(unsigned char *md, BLAKE2B_CTX *c);
unsigned char *BLAKE2b(const unsigned char *data, size_t datalen,
                       const unsigned char *key, size_t keylen,
                       unsigned char *md);

int BLAKE2s_Init(BLAKE2S_CTX *c);
int BLAKE2s_InitKey(BLAKE2S_CTX *c, const void *key, size_t keylen);
int BLAKE2s_Update(BLAKE2S_CTX *c, const void *data, size_t datalen);
int BLAKE2s_Final(unsigned char *md, BLAKE2S_CTX *c);
unsigned char *BLAKE2s(const unsigned char *data, size_t datalen,
                       const unsigned char *key, size_t keylen,
                       unsigned char *md);

#ifdef  __cplusplus
}
#endif

#endif
