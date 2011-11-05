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

static void gcmtest(FILE *in, FILE *out, int encrypt)
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
	const EVP_CIPHER *gcm = NULL;
	FIPS_cipher_ctx_init(&ctx);

	while(fgets(buf,sizeof buf,in) != NULL)
		{
		fputs(buf,out);
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
			FIPS_cipherinit(&ctx, gcm, NULL, NULL, 1);
			/* Relax FIPS constraints for testing */
			M_EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, 0);
			if (encrypt == 1)
				{
				static unsigned char iv_fixed[4] = {1,2,3,4};
				if (!iv)
					iv = OPENSSL_malloc(ivlen);
				FIPS_cipherinit(&ctx, NULL, key, NULL, 1);
				FIPS_cipher_ctx_ctrl(&ctx,
						EVP_CTRL_GCM_SET_IV_FIXED,
						4, iv_fixed);
				if (!FIPS_cipher_ctx_ctrl(&ctx,
					EVP_CTRL_GCM_IV_GEN, 0, iv))
					{
					fprintf(stderr, "IV gen error\n");
					exit(1);
					}
				OutputValue("IV", iv, ivlen, out, 0);
				}
			else
				FIPS_cipherinit(&ctx, NULL, key, iv, 1);


			if (aadlen)
				FIPS_cipher(&ctx, NULL, aad, aadlen);
			if (ptlen)
				{
				ct = OPENSSL_malloc(ptlen);
				rv = FIPS_cipher(&ctx, ct, pt, ptlen);
				}
			FIPS_cipher(&ctx, NULL, NULL, 0);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG,
								taglen, tag);	
			OutputValue("CT", ct, ptlen, out, 0);
			OutputValue("Tag", tag, taglen, out, 0);
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
			FIPS_cipherinit(&ctx, gcm, NULL, NULL, 0);
			/* Relax FIPS constraints for testing */
			M_EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, 0);
			FIPS_cipherinit(&ctx, NULL, key, iv, 0);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, taglen, tag);
			if (aadlen)
				FIPS_cipher(&ctx, NULL, aad, aadlen);
			if (ptlen)
				{
				pt = OPENSSL_malloc(ptlen);
				rv = FIPS_cipher(&ctx, pt, ct, ptlen);
				}
			rv = FIPS_cipher(&ctx, NULL, NULL, 0);
			if (rv < 0)
				fprintf(out, "FAIL" RESP_EOL);
			else
				OutputValue("PT", pt, ptlen, out, 0);
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
	FIPS_cipher_ctx_cleanup(&ctx);	
	}

static void xtstest(FILE *in, FILE *out)
	{
	char buf[204800];
	char lbuf[204800];
	char *keyword, *value;
	int inlen = 0;
	int encrypt = 0;
	long l;
	unsigned char *key = NULL, *iv = NULL;
	unsigned char *inbuf = NULL, *outbuf = NULL;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *xts = NULL;
	FIPS_cipher_ctx_init(&ctx);

	while(fgets(buf,sizeof buf,in) != NULL)
		{
		fputs(buf,out);
		if (buf[0] == '[' && strlen(buf) >= 9)
			{
			if(!strncmp(buf,"[ENCRYPT]", 9))
				encrypt = 1;
			else if(!strncmp(buf,"[DECRYPT]", 9))
				encrypt = 0;
			}
		if  (!parse_line(&keyword, &value, lbuf, buf))
			continue;
		else if(!strcmp(keyword,"Key"))
			{
			key = hex2bin_m(value, &l);
			if (l == 32)
				xts = EVP_aes_128_xts();
			else if (l == 64)
				xts = EVP_aes_256_xts();
			else
				{
				fprintf(stderr, "Inconsistent Key length\n");
				exit(1);
				}
			}
		else if(!strcmp(keyword,"i"))
			{
			iv = hex2bin_m(value, &l);
			if (l != 16)
				{
				fprintf(stderr, "Inconsistent i length\n");
				exit(1);
				}
			}
		else if(encrypt && !strcmp(keyword,"PT"))
			{
			inbuf = hex2bin_m(value, &l);
			inlen = l;
			}
		else if(!encrypt && !strcmp(keyword,"CT"))
			{
			inbuf = hex2bin_m(value, &l);
			inlen = l;
			}
		if (inbuf)
			{
			FIPS_cipherinit(&ctx, xts, key, iv, encrypt);
			outbuf = OPENSSL_malloc(inlen);
			FIPS_cipher(&ctx, outbuf, inbuf, inlen);
			OutputValue(encrypt ? "CT":"PT", outbuf, inlen, out, 0);
			OPENSSL_free(inbuf);
			OPENSSL_free(outbuf);
			OPENSSL_free(key);
			OPENSSL_free(iv);
			iv = key = inbuf = outbuf = NULL;
			}	
		}
	FIPS_cipher_ctx_cleanup(&ctx);	
	}

static void ccmtest(FILE *in, FILE *out)
	{
	char buf[200048];
	char lbuf[200048];
	char *keyword, *value;
	long l;
	unsigned char *Key = NULL, *Nonce = NULL;
	unsigned char *Adata = NULL, *Payload = NULL;
	unsigned char *CT = NULL;
	int Plen = -1, Nlen = -1, Tlen = -1, Alen = -1;
	int decr = 0;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *ccm = NULL;
	FIPS_cipher_ctx_init(&ctx);

	while(fgets(buf,sizeof buf,in) != NULL)
		{
		char *p;
		fputs(buf,out);
		redo:
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;

		/* If surrounded by square brackets zap them */
		if (keyword[0] == '[')
			{
			keyword++;
			p = strchr(value, ']');
			if (p)
				*p = 0;
			}
		/* See if we have a comma separated list of parameters
		 * if so copy rest of line back to buffer and redo later.
		 */
		p = strchr(value, ',');
		if (p)
			{
			*p = 0;
			strcpy(buf, p + 1);
			strcat(buf, "\n");
			decr = 1;
			}
		if (!strcmp(keyword,"Plen"))
			Plen = atoi(value);
		else if (!strcmp(keyword,"Nlen"))
			Nlen = atoi(value);
		else if (!strcmp(keyword,"Tlen"))
			Tlen = atoi(value);
		else if (!strcmp(keyword,"Alen"))
			Alen = atoi(value);
		if (p)
			goto redo;
		if (!strcmp(keyword,"Key"))
			{
			if (Key)
				OPENSSL_free(Key);
			Key = hex2bin_m(value, &l);
			if (l == 16)
				ccm = EVP_aes_128_ccm();
			else if (l == 24)
				ccm = EVP_aes_192_ccm();
			else if (l == 32)
				ccm = EVP_aes_256_ccm();
			else
				{
				fprintf(stderr, "Inconsistent Key length\n");
				exit(1);
				}
			}
		else if (!strcmp(keyword,"Nonce"))
			{
			if (Nonce)
				OPENSSL_free(Nonce);
			Nonce = hex2bin_m(value, &l);
			if (l != Nlen)
				{
				fprintf(stderr, "Inconsistent nonce length\n");
				exit(1);
				}
			}
		else if (!strcmp(keyword,"Payload") && !decr)
			{
			Payload = hex2bin_m(value, &l);
			if (Plen && l != Plen)
				{
				fprintf(stderr, "Inconsistent Payload length\n");
				exit(1);
				}
			}
		else if (!strcmp(keyword,"Adata"))
			{
			if (Adata)
				OPENSSL_free(Adata);
			Adata = hex2bin_m(value, &l);
			if (Alen && l != Alen)
				{
				fprintf(stderr, "Inconsistent Payload length\n");
				exit(1);
				}
			}
		else if (!strcmp(keyword,"CT") && decr)
			{
			CT = hex2bin_m(value, &l);
			if (l != (Plen + Tlen))
				{
				fprintf(stderr, "Inconsistent CT length\n");
				exit(1);
				}
			}
		if (Payload)
			{
			FIPS_cipherinit(&ctx, ccm, NULL, NULL, 1);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Nlen, 0);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, Tlen, 0);
			FIPS_cipherinit(&ctx, NULL, Key, Nonce, 1);

			FIPS_cipher(&ctx, NULL, NULL, Plen);
			FIPS_cipher(&ctx, NULL, Adata, Alen);
			CT = OPENSSL_malloc(Plen + Tlen);
			FIPS_cipher(&ctx, CT, Payload, Plen);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, Tlen,
						CT + Plen);
			OutputValue("CT", CT, Plen + Tlen, out, 0);
			OPENSSL_free(CT);
			OPENSSL_free(Payload);
			CT = Payload = NULL;
			}
		if (CT)
			{
			int rv;
			int len = Plen == 0 ? 1: Plen;
			FIPS_cipherinit(&ctx, ccm, NULL, NULL, 0);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Nlen, 0);
			FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG,
						Tlen, CT + Plen);
			FIPS_cipherinit(&ctx, NULL, Key, Nonce, 0);
			FIPS_cipher(&ctx, NULL, NULL, Plen);
			FIPS_cipher(&ctx, NULL, Adata, Alen);
			Payload = OPENSSL_malloc(len);
			rv = FIPS_cipher(&ctx, Payload, CT, Plen);
			if (rv >= 0)
				{
				if (rv == 0)
					Payload[0] = 0;
				fputs("Result = Pass" RESP_EOL, out);
				OutputValue("Payload", Payload, len, out, 0);
				}
			else
				fputs("Result = Fail" RESP_EOL, out);
			OPENSSL_free(CT);
			OPENSSL_free(Payload);
			CT = Payload = NULL;
			}
		}
	if (Key)
		OPENSSL_free(Key);
	if (Nonce)
		OPENSSL_free(Nonce);
	if (Adata)
		OPENSSL_free(Adata);
	FIPS_cipher_ctx_cleanup(&ctx);
	}

#ifdef FIPS_ALGVS
int fips_gcmtest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	int encrypt;
	int xts = 0, ccm = 0;
	FILE *in, *out;
	if (argc == 4)
		{
		in = fopen(argv[2], "r");
		if (!in)
			{
			fprintf(stderr, "Error opening input file\n");
			exit(1);
			}
		out = fopen(argv[3], "w");
		if (!out)
			{
			fprintf(stderr, "Error opening output file\n");
			exit(1);
			}
		}
	else if (argc == 2)
		{
		in = stdin;
		out = stdout;
		}
	else
		{
		fprintf(stderr,"%s [-encrypt|-decrypt]\n",argv[0]);
		exit(1);
		}
	fips_algtest_init();
	if(!strcmp(argv[1],"-encrypt"))
		encrypt = 1;
	else if(!strcmp(argv[1],"-encryptIVext"))
		encrypt = 2;
	else if(!strcmp(argv[1],"-decrypt"))
		encrypt = 0;
	else if(!strcmp(argv[1],"-ccm"))
		ccm = 1;
	else if(!strcmp(argv[1],"-xts"))
		xts = 1;
	else
		{
		fprintf(stderr,"Don't know how to %s.\n",argv[1]);
		exit(1);
		}

	if (ccm)
		ccmtest(in, out);
	else if (xts)
		xtstest(in, out);
	else
		gcmtest(in, out, encrypt);

	if (argc == 4)
		{
		fclose(in);
		fclose(out);
		}

	return 0;
}

#endif
