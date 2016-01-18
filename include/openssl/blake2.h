/*
 * BLAKE2 reference source code package - reference C implementations
 *
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 *
 * This version of BLAKE2 has been contributed under the OpenSSL license to the
 * OpenSSL project by the BKAKE2 authors.  More information about the BLAKE2
 * hash function can be found at https://blake2.net.
 */

/* crypto/blake2/blake2.h */
/* ====================================================================
 * Copyright (c) 2012 Samuel Neves.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

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
