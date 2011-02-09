/* fips/aes/fips_gcmtest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */


#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS GCM support\n");
    return(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static void gcmtest(int encrypt)
	{
	char buf[2048];
	char lbuf[2048];
	char *keyword, *value;
	int keylen = -1, ivlen = -1, aadlen = -1, taglen = -1, ptlen = -1;
	int rv;
	long l;
	unsigned char *key = NULL, *iv = NULL, *aad = NULL, *tag = NULL;
	unsigned char *ct = NULL, *pt = NULL;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *gcm;
	EVP_CIPHER_CTX_init(&ctx);

	while(fgets(buf,sizeof buf,stdin) != NULL)
		{
		fputs(buf,stdout);
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		if(!strcmp(keyword,"[Keylen"))
			{
			keylen = atoi(value);
			if (keylen == 128)
				gcm = EVP_aes_128_gcm();
			else if (keylen == 192)
				gcm = EVP_aes_192_gcm();
			else if (keylen == 256)
				gcm = EVP_aes_256_gcm();
			else 
				{
				fprintf(stderr, "Unsupported keylen %d\n",
							keylen);
				}
			keylen >>= 3;
			}
		else if (!strcmp(keyword, "[IVlen"))
			ivlen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[AADlen"))
			aadlen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[Taglen"))
			taglen = atoi(value) >> 3;
		else if (!strcmp(keyword, "[PTlen"))
			ptlen = atoi(value) >> 3;
		else if(!strcmp(keyword,"Key"))
			{
			key = hex2bin_m(value, &l);
			if (l != keylen)
				{
				fprintf(stderr, "Inconsistent Key length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"IV"))
			{
			iv = hex2bin_m(value, &l);
			if (l != ivlen)
				{
				fprintf(stderr, "Inconsistent IV length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"PT"))
			{
			pt = hex2bin_m(value, &l);
			if (l != ptlen)
				{
				fprintf(stderr, "Inconsistent PT length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"CT"))
			{
			ct = hex2bin_m(value, &l);
			if (l != ptlen)
				{
				fprintf(stderr, "Inconsistent CT length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"AAD"))
			{
			aad = hex2bin_m(value, &l);
			if (l != aadlen)
				{
				fprintf(stderr, "Inconsistent AAD length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"Tag"))
			{
			tag = hex2bin_m(value, &l);
			if (l != taglen)
				{
				fprintf(stderr, "Inconsistent Tag length\n");
				exit(1);
				}
			}
		if (encrypt && pt && aad && (iv || encrypt==1))
			{
			tag = OPENSSL_malloc(taglen);
			EVP_CipherInit_ex(&ctx, gcm, NULL, NULL, NULL, 1);
			EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, 0);
			if (encrypt == 1)
				{
				static unsigned char iv_fixed[4] = {1,2,3,4};
				if (!iv)
					iv = OPENSSL_malloc(ivlen);
				EVP_CipherInit_ex(&ctx, NULL, NULL, key, NULL, 1);
				EVP_CIPHER_CTX_ctrl(&ctx,
						EVP_CTRL_GCM_SET_IV_FIXED,
						4, iv_fixed);
				if (!EVP_CIPHER_CTX_ctrl(&ctx,
					EVP_CTRL_GCM_IV_GEN, 0, iv))
					{
					fprintf(stderr, "IV gen error\n");
					exit(1);
					}
				OutputValue("IV", iv, ivlen, stdout, 0);
				}
			else
				EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, 1);


			if (aadlen)
				EVP_Cipher(&ctx, NULL, aad, aadlen);
			if (ptlen)
				{
				ct = OPENSSL_malloc(ptlen);
				rv = EVP_Cipher(&ctx, ct, pt, ptlen);
				}
			EVP_Cipher(&ctx, NULL, NULL, 0);
			EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG,
								taglen, tag);	
			OutputValue("CT", ct, ptlen, stdout, 0);
			OutputValue("Tag", tag, taglen, stdout, 0);
			if (iv)
				OPENSSL_free(iv);
			if (aad)
				OPENSSL_free(aad);
			if (ct)
				OPENSSL_free(ct);
			if (pt)
				OPENSSL_free(pt);
			if (key)
				OPENSSL_free(key);
			if (tag)
				OPENSSL_free(tag);
			iv = aad = ct = pt = key = tag = NULL;
			}	
		if (!encrypt && tag)
			{
			EVP_CipherInit_ex(&ctx, gcm, NULL, NULL, NULL, 0);
			EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, 0);
			EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, 0);
			EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, taglen, tag);
			if (aadlen)
				EVP_Cipher(&ctx, NULL, aad, aadlen);
			if (ptlen)
				{
				pt = OPENSSL_malloc(ptlen);
				rv = EVP_Cipher(&ctx, pt, ct, ptlen);
				}
			rv = EVP_Cipher(&ctx, NULL, NULL, 0);
			if (rv < 0)
				printf("FAIL\n");
			else
				OutputValue("PT", pt, ptlen, stdout, 0);
			if (iv)
				OPENSSL_free(iv);
			if (aad)
				OPENSSL_free(aad);
			if (ct)
				OPENSSL_free(ct);
			if (pt)
				OPENSSL_free(pt);
			if (key)
				OPENSSL_free(key);
			if (tag)
				OPENSSL_free(tag);
			iv = aad = ct = pt = key = tag = NULL;
			}
		}
	}

int main(int argc,char **argv)
	{
	int encrypt;
	if(argc != 2)
		{
		fprintf(stderr,"%s [-encrypt|-decrypt]\n",argv[0]);
		exit(1);
		}
	fips_set_error_print();
	if(!FIPS_mode_set(1))
		exit(1);
	if(!strcmp(argv[1],"-encrypt"))
		encrypt = 1;
	else if(!strcmp(argv[1],"-encryptIVext"))
		encrypt = 2;
	else if(!strcmp(argv[1],"-decrypt"))
		encrypt = 0;
	else
		{
		fprintf(stderr,"Don't know how to %s.\n",argv[1]);
		exit(1);
		}

	gcmtest(encrypt);

	return 0;
}

#endif
