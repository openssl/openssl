/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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
 *
 */

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include <stdio.h>
#include <stdlib.h>

int FIPS_selftest_fail;

static void hmac_init(SHA_CTX *md_ctx,SHA_CTX *i_ctx,SHA_CTX *o_ctx,
		      const char *key)
    {
    int len=strlen(key);
    int i;
    unsigned char keymd[HMAC_MAX_MD_CBLOCK];
    unsigned char pad[HMAC_MAX_MD_CBLOCK];

    if (len > SHA_CBLOCK)
	{
	//	EVP_DigestInit_ex(&ctx->md_ctx,md, impl);
	SHA1_Init(md_ctx);
	//	EVP_DigestUpdate(&ctx->md_ctx,key,len);
	SHA1_Update(md_ctx,key,len);
	//	EVP_DigestFinal_ex(&(ctx->md_ctx),ctx->key,&ctx->key_length);
	SHA1_Final(keymd,md_ctx);
	len=20;
	}
    else
	memcpy(keymd,key,len);
    memset(&keymd[len],'\0',HMAC_MAX_MD_CBLOCK-len);

    for(i=0 ; i < HMAC_MAX_MD_CBLOCK ; i++)
	pad[i]=0x36^keymd[i];
    //    EVP_DigestInit_ex(&ctx->i_ctx,md, impl);
    SHA1_Init(md_ctx);
    //    EVP_DigestUpdate(&ctx->i_ctx,pad,EVP_MD_block_size(md));
    SHA1_Update(md_ctx,pad,SHA_CBLOCK);

    for(i=0 ; i < HMAC_MAX_MD_CBLOCK ; i++)
	pad[i]=0x5c^keymd[i];
    //    EVP_DigestInit_ex(&ctx->o_ctx,md, impl);
    SHA1_Init(o_ctx);
    //    EVP_DigestUpdate(&ctx->o_ctx,pad,EVP_MD_block_size(md));
    SHA1_Update(o_ctx,pad,SHA_CBLOCK);
    //    EVP_MD_CTX_copy_ex(&ctx->md_ctx,&ctx->i_ctx);
    //    memcpy(md_ctx,i_ctx,sizeof *md_ctx);
    }

static void hmac_final(unsigned char *md,SHA_CTX *md_ctx,SHA_CTX *o_ctx)
    {
    unsigned char buf[20];

    //EVP_DigestFinal_ex(&ctx->md_ctx,buf,&i);
    SHA1_Final(buf,md_ctx);
    //EVP_MD_CTX_copy_ex(&ctx->md_ctx,&ctx->o_ctx);
    //    memcpy(md_ctx,o_ctx,sizeof *md_ctx);
    //EVP_DigestUpdate(&ctx->md_ctx,buf,i);
    SHA1_Update(o_ctx,buf,sizeof buf);
    //EVP_DigestFinal_ex(&ctx->md_ctx,md,len);
    SHA1_Final(md,o_ctx);
    }

int main(int argc,char **argv)
    {
#ifdef OPENSSL_FIPS
    static char key[]="etaonrishdlcupfm";
    int n;

    if(argc < 2)
	{
	fprintf(stderr,"%s [<file>]+\n",argv[0]);
	exit(1);
	}

    for(n=1 ; n < argc ; ++n)
	{
	FILE *f=fopen(argv[n],"rb");
	SHA_CTX md_ctx,i_ctx,o_ctx;
	unsigned char md[20];
	int i;

	if(!f)
	    {
	    perror(argv[n]);
	    exit(2);
	    }

	hmac_init(&md_ctx,&i_ctx,&o_ctx,key);
	for( ; ; )
	    {
	    char buf[1024];
	    int l=fread(buf,1,sizeof buf,f);

	    if(l == 0)
		{
		if(ferror(f))
		    {
		    perror(argv[n]);
		    exit(3);
		    }
		else
		    break;
		}
	    SHA1_Update(&md_ctx,buf,l);
	    }
	hmac_final(md,&md_ctx,&o_ctx);

	printf("HMAC-SHA1(%s)= ",argv[n]);
	for(i=0 ; i < 20 ; ++i)
	    printf("%02x",md[i]);
	printf("\n");
	}
#endif
    return 0;
    }


