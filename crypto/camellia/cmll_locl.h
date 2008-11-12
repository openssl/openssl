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

typedef unsigned int  u32;
typedef unsigned char u8;

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
# if _MSC_VER >= 1400
#  define SWAP(x) _byteswap_ulong(x)
# else
#  define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# endif
# define GETU32(p)   SWAP(*((u32 *)(p)))
# define PUTU32(p,v) (*((u32 *)(p)) = SWAP((v)))
#elif defined(__GNUC__) && __GNUC__>=2 && (defined(__i386) || defined(__x86_64))
# if defined(B_ENDIAN) /* stratus.com does it */
#  define GETU32(p)   (*(u32 *)(p))
#  define PUTU32(p,v) (*(u32 *)(p)=(v))
# else
#  define GETU32(p)   ({u32 r=*(const u32 *)(p); asm("bswapl %0":"=r"(r):"0"(r)); r; })
#  define PUTU32(p,v) ({u32 r=(v); asm("bswapl %0":"=r"(r):"0"(r)); *(u32 *)(p)=r; })
# endif
#elif defined(__s390__) || defined(__s390x__)
# define GETU32(p)   (*(u32 *)(p))
# define PUTU32(p,v) (*(u32 *)(p)=(v))
#else
# define GETU32(p)   (((u32)(p)[0] << 24) ^ ((u32)(p)[1] << 16) ^ ((u32)(p)[2] <<  8) ^ ((u32)(p)[3]))
# define PUTU32(p,v) ((p)[0] = (u8)((v) >> 24), (p)[1] = (u8)((v) >> 16), (p)[2] = (u8)((v) >>  8), (p)[3] = (u8)(v))
#endif

int Camellia_Ekeygen(int keyBitLength, const u8 *rawKey, KEY_TABLE_TYPE keyTable);
void Camellia_EncryptBlock_Rounds(int grandRounds, const u8 plaintext[], 
		const KEY_TABLE_TYPE keyTable, u8 ciphertext[]);
void Camellia_DecryptBlock_Rounds(int grandRounds, const u8 ciphertext[], 
		const KEY_TABLE_TYPE keyTable, u8 plaintext[]);
void Camellia_EncryptBlock(int keyBitLength, const u8 plaintext[], 
		const KEY_TABLE_TYPE keyTable, u8 ciphertext[]);
void Camellia_DecryptBlock(int keyBitLength, const u8 ciphertext[], 
		const KEY_TABLE_TYPE keyTable, u8 plaintext[]);
#endif /* #ifndef HEADER_CAMELLIA_LOCL_H */
