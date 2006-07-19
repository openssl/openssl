/* crypto/camellia/camellia_locl.h -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright 2006 NTT (Nippon Telegraph and Telephone Corporation) . 
 * ALL RIGHTS RESERVED.
 *
 * Intellectual Property information for Camellia:
 *     http://info.isl.ntt.co.jp/crypt/eng/info/chiteki.html
 *
 * News Release for Announcement of Camellia open source:
 *     http://www.ntt.co.jp/news/news06e/0604/060413a.html
 *
 * The Camellia Code included herein is developed by
 * NTT (Nippon Telegraph and Telephone Corporation), and is contributed
 * to the OpenSSL project.
 *
 * The Camellia Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#ifndef HEADER_CAMELLIA_LOCL_H
#define HEADER_CAMELLIA_LOCL_H

#include "openssl/e_os2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;
#else
#include <inttypes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ALIGN 4
#define UNITSIZE 4

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
# define SWAP(x) ( _lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00 )
# define GETU32(p) SWAP(*((uint32_t *)(p)))
# define PUTU32(ct, st) { *((uint32_t *)(ct)) = SWAP((st)); }
# define CAMELLIA_SWAP4(x) (x = ( _lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00) )


#else /* not windows */
# define GETU32(pt) (((uint32_t)(pt)[0] << 24) \
	^ ((uint32_t)(pt)[1] << 16) \
	^ ((uint32_t)(pt)[2] <<  8) \
	^ ((uint32_t)(pt)[3]))

# define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); \
	(ct)[1] = (uint8_t)((st) >> 16); \
	(ct)[2] = (uint8_t)((st) >>  8); \
	(ct)[3] = (uint8_t)(st); }

#ifdef L_ENDIAN
#if (defined (__GNUC__) && !defined(i386))
#define CAMELLIA_SWAP4(x) \
  do{\
    asm("bswap %1" : "+r" (x));\
  }while(0)
#else /* not gcc */
#define CAMELLIA_SWAP4(x) \
   do{\
     x = ((uint32_t)x << 16) + ((uint32_t)x >> 16);\
     x = (((uint32_t)x & 0xff00ff) << 8) + (((uint32_t)x >> 8) & 0xff00ff);\
   } while(0)
#endif /* not gcc */
#else /* big endian */
#define CAMELLIA_SWAP4(x)
#endif /* L_ENDIAN */
#endif

#define COPY4WORD(dst, src)	 \
	     do			 \
		     {		 \
		     (dst)[0]=(src)[0];		\
		     (dst)[1]=(src)[1];		\
		     (dst)[2]=(src)[2];		\
		     (dst)[3]=(src)[3];		\
		     }while(0)

#define SWAP4WORD(word)				\
   do						\
	   {					\
	   CAMELLIA_SWAP4((word)[0]);			\
	   CAMELLIA_SWAP4((word)[1]);			\
	   CAMELLIA_SWAP4((word)[2]);			\
	   CAMELLIA_SWAP4((word)[3]);			\
	   }while(0)

#define XOR4WORD(a, b)/* a = a ^ b */		\
   do						\
	{					\
	(a)[0]^=(b)[0];				\
	(a)[1]^=(b)[1];				\
	(a)[2]^=(b)[2];				\
	(a)[3]^=(b)[3];				\
	}while(0)

#define XOR4WORD2(a, b, c)/* a = b ^ c */	\
   do						\
	{					\
	(a)[0]=(b)[0]^(c)[0];			\
	(a)[1]=(b)[1]^(c)[1];				\
	(a)[2]=(b)[2]^(c)[2];				\
	(a)[3]=(b)[3]^(c)[3];				\
	}while(0)


void camellia_setup128(const unsigned char *key, uint32_t *subkey);
void camellia_setup192(const unsigned char *key, uint32_t *subkey);
void camellia_setup256(const unsigned char *key, uint32_t *subkey);

void camellia_encrypt128(const uint32_t *subkey, uint32_t *io);
void camellia_decrypt128(const uint32_t *subkey, uint32_t *io);
void camellia_encrypt256(const uint32_t *subkey, uint32_t *io);
void camellia_decrypt256(const uint32_t *subkey, uint32_t *io);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef HEADER_CAMELLIA_LOCL_H */

