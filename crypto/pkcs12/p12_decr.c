/* p12_decr.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/pkcs12.h>

/* Define this to dump decrypted output to files called DERnnn */
/*#define DEBUG_DECRYPT*/


/* Encrypt/Decrypt a buffer based on password and algor, result in a
 * OPENSSL_malloc'ed buffer
 */

unsigned char * PKCS12_pbe_crypt (X509_ALGOR *algor, const char *pass,
	     int passlen, unsigned char *in, int inlen, unsigned char **data,
	     int *datalen, int en_de)
{
	unsigned char *out;
	int outlen, i;
	EVP_CIPHER_CTX ctx;

	/* Decrypt data */
        if (!EVP_PBE_CipherInit (algor->algorithm, pass, passlen,
					 algor->parameter, &ctx, en_de)) {
		PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR);
		return NULL;
	}

	if(!(out = OPENSSL_malloc (inlen + EVP_CIPHER_CTX_block_size(&ctx)))) {
		PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	EVP_CipherUpdate (&ctx, out, &i, in, inlen);
	outlen = i;
	if(!EVP_CipherFinal (&ctx, out + i, &i)) {
		OPENSSL_free (out);
		PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,PKCS12_R_PKCS12_CIPHERFINAL_ERROR);
		return NULL;
	}
	outlen += i;
	if (datalen) *datalen = outlen;
	if (data) *data = out;
	return out;

}

/* Decrypt an OCTET STRING and decode ASN1 structure 
 * if seq & 1 'obj' is a stack of structures to be encoded
 * if seq & 2 zero buffer after use
 * as a sequence.
 */

char * PKCS12_decrypt_d2i (X509_ALGOR *algor, char * (*d2i)(),
	     void (*free_func)(void *), const char *pass, int passlen,
	     ASN1_OCTET_STRING *oct, int seq)
{
	unsigned char *out, *p;
	char *ret;
	int outlen;

	if (!PKCS12_pbe_crypt (algor, pass, passlen, oct->data, oct->length,
			       &out, &outlen, 0)) {
		PKCS12err(PKCS12_F_PKCS12_DECRYPT_D2I,PKCS12_R_PKCS12_PBE_CRYPT_ERROR);
		return NULL;
	}
	p = out;
#ifdef DEBUG_DECRYPT
	{
		FILE *op;

		char fname[30];
		static int fnm = 1;
		sprintf(fname, "DER%d", fnm++);
		op = fopen(fname, "wb");
		fwrite (p, 1, outlen, op);
		fclose(op);
	}
#endif
	if (seq & 1) ret = (char *) d2i_ASN1_SET(NULL, &p, outlen, d2i,
				free_func, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
	else ret = d2i(NULL, &p, outlen);
	if (seq & 2) memset(out, 0, outlen);
	if(!ret) PKCS12err(PKCS12_F_PKCS12_DECRYPT_D2I,PKCS12_R_DECODE_ERROR);
	OPENSSL_free (out);
	return ret;
}

/* Encode ASN1 structure and encrypt, return OCTET STRING 
 * if 'seq' is non-zero 'obj' is a stack of structures to be encoded
 * as a sequence
 */

ASN1_OCTET_STRING *PKCS12_i2d_encrypt (X509_ALGOR *algor, int (*i2d)(),
				       const char *pass, int passlen,
				       char *obj, int seq)
{
	ASN1_OCTET_STRING *oct;
	unsigned char *in, *p;
	int inlen;
	if (!(oct = M_ASN1_OCTET_STRING_new ())) {
		PKCS12err(PKCS12_F_PKCS12_I2D_ENCRYPT,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	if (seq) inlen = i2d_ASN1_SET((STACK *)obj, NULL, i2d, V_ASN1_SEQUENCE,
						 V_ASN1_UNIVERSAL, IS_SEQUENCE);
	else inlen = i2d (obj, NULL);
	if (!inlen) {
		PKCS12err(PKCS12_F_PKCS12_I2D_ENCRYPT,PKCS12_R_ENCODE_ERROR);
		return NULL;
	}
	if (!(in = OPENSSL_malloc (inlen))) {
		PKCS12err(PKCS12_F_PKCS12_I2D_ENCRYPT,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	p = in;
	if (seq) i2d_ASN1_SET((STACK *)obj, &p, i2d, V_ASN1_SEQUENCE,
						 V_ASN1_UNIVERSAL, IS_SEQUENCE);
	else i2d (obj, &p);
	if (!PKCS12_pbe_crypt (algor, pass, passlen, in, inlen, &oct->data,
				 &oct->length, 1)) {
		PKCS12err(PKCS12_F_PKCS12_I2D_ENCRYPT,PKCS12_R_ENCRYPT_ERROR);
		OPENSSL_free(in);
		return NULL;
	}
	OPENSSL_free (in);
	return oct;
}

IMPLEMENT_PKCS12_STACK_OF(PKCS7)
