/* crypto/evp/evp_key.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include "x509.h"
#include "objects.h"
#include "evp.h"

/* should be init to zeros. */
static char prompt_string[80];

void EVP_set_pw_prompt(prompt)
char *prompt;
	{
	if (prompt == NULL)
		prompt_string[0]='\0';
	else
		strncpy(prompt_string,prompt,79);
	}

char *EVP_get_pw_prompt()
	{
	if (prompt_string[0] == '\0')
		return(NULL);
	else
		return(prompt_string);
	}

#ifdef NO_DES
int des_read_pw_string(char *buf,int len,char *prompt,int verify);
#endif

int EVP_read_pw_string(buf,len,prompt,verify)
char *buf;
int len;
char *prompt;
int verify;
	{
	if ((prompt == NULL) && (prompt_string[0] != '\0'))
		prompt=prompt_string;
	return(des_read_pw_string(buf,len,prompt,verify));
	}

int EVP_BytesToKey(type,md,salt,data,datal,count,key,iv)
EVP_CIPHER *type;
EVP_MD *md;
unsigned char *salt;
unsigned char *data;
int datal;
int count;
unsigned char *key;
unsigned char *iv;
	{
	EVP_MD_CTX c;
	unsigned char md_buf[EVP_MAX_MD_SIZE];
	int niv,nkey,addmd=0;
	unsigned int mds=0,i;

	nkey=type->key_len;
	niv=type->iv_len;

	if (data == NULL) return(nkey);

	for (;;)
		{
		EVP_DigestInit(&c,md);
		if (addmd++)
			EVP_DigestUpdate(&c,&(md_buf[0]),mds);
		EVP_DigestUpdate(&c,data,datal);
		if (salt != NULL)
			EVP_DigestUpdate(&c,salt,8);
		EVP_DigestFinal(&c,&(md_buf[0]),&mds);

		for (i=1; i<(unsigned int)count; i++)
			{
			EVP_DigestInit(&c,md);
			EVP_DigestUpdate(&c,&(md_buf[0]),mds);
			EVP_DigestFinal(&c,&(md_buf[0]),&mds);
			}
		i=0;
		if (nkey)
			{
			for (;;)
				{
				if (nkey == 0) break;
				if (i == mds) break;
				if (key != NULL)
					*(key++)=md_buf[i];
				nkey--;
				i++;
				}
			}
		if (niv && (i != mds))
			{
			for (;;)
				{
				if (niv == 0) break;
				if (i == mds) break;
				if (iv != NULL)
					*(iv++)=md_buf[i];
				niv--;
				i++;
				}
			}
		if ((nkey == 0) && (niv == 0)) break;
		}
	memset(&c,0,sizeof(c));
	memset(&(md_buf[0]),0,EVP_MAX_MD_SIZE);
	return(type->key_len);
	}

