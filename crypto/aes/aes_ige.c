/* crypto/aes/aes_ige.c -*- mode:C; c-file-style: "eay" -*- */
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

#include "cryptlib.h"

#include <openssl/aes.h>
#include "aes_locl.h"

/*
static void hexdump(FILE *f,const char *title,const unsigned char *s,int l)
    {
    int n=0;

    fprintf(f,"%s",title);
    for( ; n < l ; ++n)
		{
		if((n%16) == 0)
			fprintf(f,"\n%04x",n);
		fprintf(f," %02x",s[n]);
		}
    fprintf(f,"\n");
    }
*/

/* N.B. The IV for this mode is _twice_ the block size */

void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
					 const unsigned long length, const AES_KEY *key,
					 unsigned char *ivec, const int enc)
	{
	unsigned long n;
	unsigned long len = length;
	unsigned char tmp[AES_BLOCK_SIZE];
	unsigned char tmp2[AES_BLOCK_SIZE];
	unsigned char prev[AES_BLOCK_SIZE];
	const unsigned char *iv = ivec;
	const unsigned char *iv2 = ivec + AES_BLOCK_SIZE;

	OPENSSL_assert(in && out && key && ivec);
	OPENSSL_assert((AES_ENCRYPT == enc)||(AES_DECRYPT == enc));
	OPENSSL_assert((length%AES_BLOCK_SIZE) == 0);

	if (AES_ENCRYPT == enc)
		{
		/* XXX: Do a separate case for when in != out (strictly should
		   check for overlap, too) */
		while (len >= AES_BLOCK_SIZE)
			{
			/*			hexdump(stdout, "in", in, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", iv, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] = in[n] ^ iv[n];
			/*			hexdump(stdout, "in ^ iv", out, AES_BLOCK_SIZE); */
			AES_encrypt(out, out, key);
			/*			hexdump(stdout,"enc", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout,"iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv2[n];
			/*			hexdump(stdout,"out", out, AES_BLOCK_SIZE); */
			iv = out;
			memcpy(prev, in, AES_BLOCK_SIZE);
			iv2 = prev;
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
			}
		memcpy(ivec, iv, AES_BLOCK_SIZE);
		memcpy(ivec + AES_BLOCK_SIZE, iv2, AES_BLOCK_SIZE);
		}
	else
		{
		while (len >= AES_BLOCK_SIZE)
			{
			memcpy(tmp, in, AES_BLOCK_SIZE);
			memcpy(tmp2, in, AES_BLOCK_SIZE);
			/*			hexdump(stdout, "in", in, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				tmp[n] ^= iv2[n];
			/*			hexdump(stdout, "in ^ iv2", tmp, AES_BLOCK_SIZE); */
			AES_decrypt(tmp, out, key);
			/*			hexdump(stdout, "dec", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", ivec, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= ivec[n];
			/*			hexdump(stdout, "out", out, AES_BLOCK_SIZE); */
			memcpy(ivec, tmp2, AES_BLOCK_SIZE);
			iv2 = out;
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
			}
		memcpy(ivec + AES_BLOCK_SIZE, iv2, AES_BLOCK_SIZE);
		}
	}

/*
 * Note that its effectively impossible to do biIGE in anything other
 * than a single pass, so no provision is made for chaining.
 */

/* N.B. The IV for this mode is _four times_ the block size */

void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
						const unsigned long length, const AES_KEY *key,
						const AES_KEY *key2, const unsigned char *ivec,
						const int enc)
	{
	unsigned long n;
	unsigned long len = length;
	unsigned char tmp[AES_BLOCK_SIZE];
	unsigned char tmp2[AES_BLOCK_SIZE];
	unsigned char tmp3[AES_BLOCK_SIZE];
	unsigned char prev[AES_BLOCK_SIZE];
	const unsigned char *iv;
	const unsigned char *iv2;

	OPENSSL_assert(in && out && key && ivec);
	OPENSSL_assert((AES_ENCRYPT == enc)||(AES_DECRYPT == enc));
	OPENSSL_assert((length%AES_BLOCK_SIZE) == 0);

	if (AES_ENCRYPT == enc)
		{
		/* XXX: Do a separate case for when in != out (strictly should
		   check for overlap, too) */

		/* First the forward pass */ 
		iv = ivec;
		iv2 = ivec + AES_BLOCK_SIZE;
		while (len >= AES_BLOCK_SIZE)
			{
			/*			hexdump(stdout, "in", in, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", iv, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] = in[n] ^ iv[n];
			/*			hexdump(stdout, "in ^ iv", out, AES_BLOCK_SIZE); */
			AES_encrypt(out, out, key);
			/*			hexdump(stdout,"enc", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout,"iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv2[n];
			/*			hexdump(stdout,"out", out, AES_BLOCK_SIZE); */
			iv = out;
			memcpy(prev, in, AES_BLOCK_SIZE);
			iv2 = prev;
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
			}

		/* And now backwards */
		iv = ivec + AES_BLOCK_SIZE*2;
		iv2 = ivec + AES_BLOCK_SIZE*3;
		len = length;
		while(len >= AES_BLOCK_SIZE)
			{
			out -= AES_BLOCK_SIZE;
			/*			hexdump(stdout, "intermediate", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", iv, AES_BLOCK_SIZE); */
			/* XXX: reduce copies by alternating between buffers */
			memcpy(tmp, out, AES_BLOCK_SIZE);
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv[n];
			/*			hexdump(stdout, "out ^ iv", out, AES_BLOCK_SIZE); */
			AES_encrypt(out, out, key);
			/*			hexdump(stdout,"enc", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout,"iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv2[n];
			/*			hexdump(stdout,"out", out, AES_BLOCK_SIZE); */
			iv = out;
			memcpy(prev, tmp, AES_BLOCK_SIZE);
			iv2 = prev;
			len -= AES_BLOCK_SIZE;
			}
		}
	else
		{
		/* First backwards */
		iv = ivec + AES_BLOCK_SIZE*2;
		iv2 = ivec + AES_BLOCK_SIZE*3;
		in += length;
		out += length;
		while (len >= AES_BLOCK_SIZE)
			{
			in -= AES_BLOCK_SIZE;
			out -= AES_BLOCK_SIZE;
			memcpy(tmp, in, AES_BLOCK_SIZE);
			memcpy(tmp2, in, AES_BLOCK_SIZE);
			/*			hexdump(stdout, "in", in, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				tmp[n] ^= iv2[n];
			/*			hexdump(stdout, "in ^ iv2", tmp, AES_BLOCK_SIZE); */
			AES_decrypt(tmp, out, key);
			/*			hexdump(stdout, "dec", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", iv, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv[n];
			/*			hexdump(stdout, "out", out, AES_BLOCK_SIZE); */
			memcpy(tmp3, tmp2, AES_BLOCK_SIZE);
			iv = tmp3;
			iv2 = out;
			len -= AES_BLOCK_SIZE;
			}

		/* And now forwards */
		iv = ivec;
		iv2 = ivec + AES_BLOCK_SIZE;
		len = length;
		while (len >= AES_BLOCK_SIZE)
			{
			memcpy(tmp, out, AES_BLOCK_SIZE);
			memcpy(tmp2, out, AES_BLOCK_SIZE);
			/*			hexdump(stdout, "intermediate", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv2", iv2, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				tmp[n] ^= iv2[n];
			/*			hexdump(stdout, "out ^ iv2", tmp, AES_BLOCK_SIZE); */
			AES_decrypt(tmp, out, key);
			/*			hexdump(stdout, "dec", out, AES_BLOCK_SIZE); */
			/*			hexdump(stdout, "iv", ivec, AES_BLOCK_SIZE); */
			for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
				out[n] ^= iv[n];
			/*			hexdump(stdout, "out", out, AES_BLOCK_SIZE); */
			memcpy(tmp3, tmp2, AES_BLOCK_SIZE);
			iv = tmp3;
			iv2 = out;
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
			}

		}
	}
