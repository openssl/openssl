/* crypto/camellia/camellia_cbc.c -*- mode:C; c-file-style: "eay" -*- */
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
 *
 */

#ifndef CAMELLIA_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/camellia.h>
#include "cmll_locl.h"

void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     const unsigned long length, const CAMELLIA_KEY *key,
		     unsigned char *ivec, const int enc) {

	unsigned long n;
	unsigned long len = length;
	unsigned char tmp[CAMELLIA_BLOCK_SIZE];
	const unsigned char *iv = ivec;
	uint32_t t32[UNITSIZE];


	assert(in && out && key && ivec);
	assert((CAMELLIA_ENCRYPT == enc)||(CAMELLIA_DECRYPT == enc));

	if(((size_t)in) % ALIGN == 0
		&& ((size_t)out) % ALIGN == 0
		&& ((size_t)ivec) % ALIGN == 0)
		{
		if (CAMELLIA_ENCRYPT == enc)
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				XOR4WORD2((uint32_t *)out,
					(uint32_t *)in, (uint32_t *)iv);
				key->enc(key->rd_key, (uint32_t *)out);
				iv = out;
				len -= CAMELLIA_BLOCK_SIZE;
				in += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				for(n=0; n < len; ++n)
					out[n] = in[n] ^ iv[n];
				for(n=len; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] = iv[n];
				key->enc(key->rd_key, (uint32_t *)out);
				iv = out;
				}
			memcpy(ivec,iv,CAMELLIA_BLOCK_SIZE);
			}
		else if (in != out)
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				memcpy(out,in,CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key,(uint32_t *)out);
				XOR4WORD((uint32_t *)out, (uint32_t *)iv);
				iv = in;
				len -= CAMELLIA_BLOCK_SIZE;
				in  += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key, (uint32_t *)tmp);
				for(n=0; n < len; ++n)
					out[n] = tmp[n] ^ iv[n];
				iv = in;
				}
			memcpy(ivec,iv,CAMELLIA_BLOCK_SIZE);
			}
		else /* in == out */
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key, (uint32_t *)out);
				XOR4WORD((uint32_t *)out, (uint32_t *)ivec);
				memcpy(ivec, tmp, CAMELLIA_BLOCK_SIZE);
				len -= CAMELLIA_BLOCK_SIZE;
				in += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key,(uint32_t *)out);
				for(n=0; n < len; ++n)
					out[n] ^= ivec[n];
				for(n=len; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] = tmp[n];
				memcpy(ivec, tmp, CAMELLIA_BLOCK_SIZE);
				}
			}
		}
	else /* no aligned */
		{
		if (CAMELLIA_ENCRYPT == enc)
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				for(n=0; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] = in[n] ^ iv[n];
				memcpy(t32, out, CAMELLIA_BLOCK_SIZE);
				key->enc(key->rd_key, t32);
				memcpy(out, t32, CAMELLIA_BLOCK_SIZE);
				iv = out;
				len -= CAMELLIA_BLOCK_SIZE;
				in += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				for(n=0; n < len; ++n)
					out[n] = in[n] ^ iv[n];
				for(n=len; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] = iv[n];
				key->enc(key->rd_key, (uint32_t *)out);
				iv = out;
				}
			memcpy(ivec,iv,CAMELLIA_BLOCK_SIZE);
			}
		else if (in != out)
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				memcpy(t32,in,CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key,t32);
				memcpy(out,t32,CAMELLIA_BLOCK_SIZE);
				for(n=0; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] ^= iv[n];
				iv = in;
				len -= CAMELLIA_BLOCK_SIZE;
				in  += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				memcpy(t32, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key, t32);
				memcpy(out, t32, CAMELLIA_BLOCK_SIZE);
				for(n=0; n < len; ++n)
					out[n] = tmp[n] ^ iv[n];
				iv = in;
				}
			memcpy(ivec,iv,CAMELLIA_BLOCK_SIZE);
			}
		else
			{
			while (len >= CAMELLIA_BLOCK_SIZE)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				memcpy(t32, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key, t32);
				memcpy(out, t32, CAMELLIA_BLOCK_SIZE);
				for(n=0; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] ^= ivec[n];
				memcpy(ivec, tmp, CAMELLIA_BLOCK_SIZE);
				len -= CAMELLIA_BLOCK_SIZE;
				in += CAMELLIA_BLOCK_SIZE;
				out += CAMELLIA_BLOCK_SIZE;
				}
			if (len)
				{
				memcpy(tmp, in, CAMELLIA_BLOCK_SIZE);
				memcpy(t32, in, CAMELLIA_BLOCK_SIZE);
				key->dec(key->rd_key,t32);
				memcpy(out, t32, CAMELLIA_BLOCK_SIZE);
				for(n=0; n < len; ++n)
					out[n] ^= ivec[n];
				for(n=len; n < CAMELLIA_BLOCK_SIZE; ++n)
					out[n] = tmp[n];
				memcpy(ivec, tmp, CAMELLIA_BLOCK_SIZE);
				}
			}
		}
}

