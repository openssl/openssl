/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory.h>
#include <assert.h>

static EVP_CIPHER rd_cipher[3][3];

static int anSizes[]={16,24,32};
static int anNIDs[3][3]=
    {
    { NID_rijndael_ecb_k128_b128,NID_rijndael_ecb_k192_b128,NID_rijndael_ecb_k256_b128 },
    { NID_rijndael_ecb_k128_b192,NID_rijndael_ecb_k192_b192,NID_rijndael_ecb_k256_b192 },
    { NID_rijndael_ecb_k128_b256,NID_rijndael_ecb_k192_b256,NID_rijndael_ecb_k256_b256 }
    };

static int rd_init_ecb(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		       const unsigned char *iv, int enc)
    {
    RIJNDAEL_KEY *k=&ctx->c.rijndael;

    k->enc=enc;
    k->rounds=ctx->cipher->key_len/4+6;
    rijndaelKeySched((const word8 (*)[4])key,k->keySched,k->rounds);
    if(!k->enc)
	rijndaelKeyEncToDec(k->keySched,k->rounds);
    memcpy(k->iv,iv,ctx->cipher->iv_len);

    return 1;
    }

static int rd_cipher_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 const unsigned char *in, unsigned int inl)
    {
    while(inl > 0)
	{
	if(ctx->c.rijndael.enc)
	    rijndaelEncrypt(in,out,ctx->c.rijndael.keySched,
			    ctx->c.rijndael.rounds);
	else
	    rijndaelDecrypt(in,out,ctx->c.rijndael.keySched,
			    ctx->c.rijndael.rounds);
	inl-=16;
	in+=16;
	out+=16;
	}
    assert(inl == 0);

    return 1;
    }

EVP_CIPHER *EVP_rijndael_ecb(int nBlockLength,int nKeyLength)
    {
    EVP_CIPHER *c;

    if(nBlockLength < 0 || nBlockLength > 2)
	{
	EVPerr(EVP_F_EVP_RIJNDAEL,EVP_R_BAD_BLOCK_LENGTH);
	return NULL;
	}
    if(nKeyLength < 0 || nKeyLength > 2)
	{
	EVPerr(EVP_F_EVP_RIJNDAEL,EVP_R_BAD_KEY_LENGTH);
	return NULL;
	}

    c=&rd_cipher[nKeyLength][nBlockLength];

    memset(c,'\0',sizeof *c);

    c->nid=anNIDs[nBlockLength][nKeyLength];
    c->block_size=anSizes[nBlockLength];
    c->key_len=anSizes[nKeyLength];
    c->iv_len=16;
    c->flags=EVP_CIPH_ECB_MODE;
    c->init=rd_init_ecb;
    c->do_cipher=rd_cipher_ecb;
    c->ctx_size=sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+
		sizeof((((EVP_CIPHER_CTX *)NULL)->c.rijndael));

    return c;
    }
