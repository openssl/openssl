/* crypto/aes/aes_cfb.c -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#include <openssl/aes.h>
#include "aes_locl.h"

/* The input and output encrypted as though 128bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */

void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long length, const AES_KEY *key,
	unsigned char *ivec, int *num, const int enc) {

	unsigned int n;
	unsigned long l = length;
	unsigned char c;

	assert(in && out && key && ivec && num);

	n = *num;

	if (enc) {
		while (l--) {
			if (n == 0) {
				AES_encrypt(ivec, ivec, key);
			}
			ivec[n] = *(out++) = *(in++) ^ ivec[n];
			n = (n+1) % AES_BLOCK_SIZE;
		}
	} else {
		while (l--) {
			if (n == 0) {
				AES_encrypt(ivec, ivec, key);
			}
			c = *(in);
			*(out++) = *(in++) ^ ivec[n];
			ivec[n] = c;
			n = (n+1) % AES_BLOCK_SIZE;
		}
	}

	*num=n;
}

/* This expects a single block of size nbits for both in and out. Note that
   it corrupts any extra bits in the last byte of out */
/* Untested, once it is working, it will be optimised */
void AES_cfbr_encrypt_block(const unsigned char *in,unsigned char *out,
			    const int nbits,const AES_KEY *key,
			    unsigned char *ivec,const int enc)
    {
    int n;
    unsigned char ovec[AES_BLOCK_SIZE*2];

    assert(in && out && key && ivec);
    if(enc)
	{
	/* construct the new IV */
	AES_encrypt(ivec,ovec,key);
	/* encrypt the input */
	for(n=0 ; n < (nbits+7)/8 ; ++n)
	    out[n]=in[n]^ovec[n];
	/* fill in the first half of the new IV with the current IV */
	memcpy(ovec,ivec,AES_BLOCK_SIZE);
	/* and put the ciphertext in the second half */
	memcpy(ovec+AES_BLOCK_SIZE,out,(nbits+7)/8);
	/* shift ovec left most of the bits... */
	memmove(ovec,ovec+nbits/8,AES_BLOCK_SIZE+(nbits%8 ? 1 : 0));
	/* now the remaining bits */
	if(nbits%8 != 0)
	    for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
		{
		ovec[n]<<=nbits%8;
		ovec[n]|=ovec[n+1]>>(8-nbits%8);
		}
	/* finally, move it back into place */
	memcpy(ivec,ovec,AES_BLOCK_SIZE);
	}
    else
	{
	/* construct the new IV in the first half of ovec */
	AES_encrypt(ivec,ovec,key);
	/* decrypt the input */
	for(n=0 ; n < (nbits+7)/8 ; ++n)
	    out[n]=in[n]^ovec[n];
	/* fill in the first half of the new IV with the current IV */
	memcpy(ovec,ivec,AES_BLOCK_SIZE);
	/* append the ciphertext */
	memcpy(ovec+AES_BLOCK_SIZE,in,(nbits+7)/8);
	/* shift ovec left most of the bits... */
	memmove(ovec,ovec+nbits/8,AES_BLOCK_SIZE+(nbits%8 ? 1 : 0));
	/* now the remaining bits */
	if(nbits%8 != 0)
	    for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
		{
		ovec[n]<<=nbits%8;
		ovec[n]|=ovec[n+1]>>(8-nbits%8);
		}
	/* finally, move it back into place */
	memcpy(ivec,ovec,AES_BLOCK_SIZE);
	}
    /* it is not necessary to cleanse ovec, since the IV is not secret */
    }

/* N.B. This expects the input to be packed, MS bit first */
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
		      const unsigned long length, const AES_KEY *key,
		      unsigned char *ivec, int *num, const int enc)
    {
    unsigned int n;
    unsigned char c[1],d[1];

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    memset(out,0,(length+7)/8);
    for(n=0 ; n < length ; ++n)
	{
	c[0]=(in[n/8]&(1 << (7-n%8))) ? 0x80 : 0;
	AES_cfbr_encrypt_block(c,d,1,key,ivec,enc);
	out[n/8]=(out[n/8]&~(1 << (7-n%8)))|((d[0]&0x80) >> (n%8));
	}
    }

void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
		      const unsigned long length, const AES_KEY *key,
		      unsigned char *ivec, int *num, const int enc)
    {
    unsigned int n;

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    for(n=0 ; n < length ; ++n)
	AES_cfbr_encrypt_block(&in[n],&out[n],8,key,ivec,enc);
    }

