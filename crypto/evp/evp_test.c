/* Written by Ben Laurie, 2001 */
/*
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

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

static int convert(unsigned char *s)
    {
    unsigned char *d;

    for(d=s ; *s ; s+=2,++d)
	{
	int n;

	if(!s[1])
	    {
	    fprintf(stderr,"Odd number of hex digits!");
	    exit(4);
	    }
	sscanf((char *)s,"%2x",&n);
	*d=(unsigned char)n;
	}
    return s-d;
    }

static unsigned char *ustrsep(char **string ,const char *delim)
    {
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, 256);
    isdelim[0] = 1;

    while (*delim)
	{
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
	}

    while (!isdelim[(unsigned char)(**string)])
	{
	while (!isdelim[(unsigned char)(**string)])
	    {
	    (*string)++;
	    }

        if (**string)
	    {
            **string = 0;
	    (*string)++;
	    }

	return token;
	}
    }

static void test1(const EVP_CIPHER *c,const unsigned char *key,int kn,
		  const unsigned char *iv,int in,
		  const unsigned char *plaintext,int pn,
		  const unsigned char *ciphertext,int cn)
    {
    EVP_CIPHER_CTX ctx;
    unsigned char out[4096];
    int outl,outl2;

    printf("Testing cipher %s\n",EVP_CIPHER_name(c));
    hexdump(stdout,"Key",key,kn);
    if(in)
	hexdump(stdout,"IV",iv,in);
    hexdump(stdout,"Plaintext",plaintext,pn);
    hexdump(stdout,"Ciphertext",ciphertext,cn);
    
    if(kn != c->key_len)
	{
	fprintf(stderr,"Key length doesn't match, got %d expected %d\n",kn,
		c->key_len);
	exit(5);
	}

    if(!EVP_EncryptInit(&ctx,c,key,iv))
	{
	fprintf(stderr,"EncryptInit failed\n");
	exit(10);
	}
    EVP_CIPHER_CTX_set_padding(&ctx,0);

    if(!EVP_EncryptUpdate(&ctx,out,&outl,plaintext,pn))
	{
	fprintf(stderr,"Encrypt failed\n");
	exit(6);
	}
    if(!EVP_EncryptFinal(&ctx,out+outl,&outl2))
	{
	fprintf(stderr,"EncryptFinal failed\n");
	exit(7);
	}

    if(outl+outl2 != cn)
	{
	fprintf(stderr,"Ciphertext length mismatch got %d expected %d\n",
		outl+outl2,cn);
	exit(8);
	}

    if(memcmp(out,ciphertext,cn))
	{
	fprintf(stderr,"Ciphertext mismatch\n");
	hexdump(stderr,"Got",out,cn);
	hexdump(stderr,"Expected",ciphertext,cn);
	exit(9);
	}

    if(!EVP_DecryptInit(&ctx,c,key,iv))
	{
	fprintf(stderr,"DecryptInit failed\n");
	exit(11);
	}
    EVP_CIPHER_CTX_set_padding(&ctx,0);

    if(!EVP_DecryptUpdate(&ctx,out,&outl,ciphertext,pn))
	{
	fprintf(stderr,"Decrypt failed\n");
	exit(6);
	}
    if(!EVP_DecryptFinal(&ctx,out+outl,&outl2))
	{
	fprintf(stderr,"DecryptFinal failed\n");
	exit(7);
	}

    if(outl+outl2 != cn)
	{
	fprintf(stderr,"Plaintext length mismatch got %d expected %d\n",
		outl+outl2,cn);
	exit(8);
	}

    if(memcmp(out,plaintext,cn))
	{
	fprintf(stderr,"Plaintext mismatch\n");
	hexdump(stderr,"Got",out,cn);
	hexdump(stderr,"Expected",plaintext,cn);
	exit(9);
	}

    printf("\n");
    }

static int test_cipher(const char *cipher,const unsigned char *key,int kn,
		       const unsigned char *iv,int in,
		       const unsigned char *plaintext,int pn,
		       const unsigned char *ciphertext,int cn)
    {
    const EVP_CIPHER *c;
    ENGINE *e;

    c=EVP_get_cipherbyname(cipher);
    if(!c)
	return 0;

    test1(c,key,kn,iv,in,plaintext,pn,ciphertext,cn);

    for(e=ENGINE_get_first() ; e ; e=ENGINE_get_next(e))
	{
	c=ENGINE_get_cipher_by_name(e,cipher);
	if(!c)
	    continue;
	printf("Testing engine %s\n",ENGINE_get_name(e));

	test1(c,key,kn,iv,in,plaintext,pn,ciphertext,cn);
	}

    return 1;
    }

static int test_digest(const char *digest,
		       const unsigned char *plaintext,int pn,
		       const unsigned char *ciphertext, int cn)
    {
    const EVP_MD *d;
    EVP_MD_CTX ctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdn;

    d=EVP_get_digestbyname(digest);
    if(!d)
	return 0;

    printf("Testing digest %s\n",EVP_MD_name(d));
    hexdump(stdout,"Plaintext",plaintext,pn);
    hexdump(stdout,"Digest",ciphertext,cn);

    EVP_MD_CTX_init(&ctx);
    if(!EVP_DigestInit(&ctx,d))
	{
	fprintf(stderr,"DigestInit failed\n");
	exit(100);
	}
    if(!EVP_DigestUpdate(&ctx,plaintext,pn))
	{
	fprintf(stderr,"DigestUpdate failed\n");
	exit(101);
	}
    if(!EVP_DigestFinal(&ctx,md,&mdn))
	{
	fprintf(stderr,"DigestUpdate failed\n");
	exit(101);
	}

    if(mdn != cn)
	{
	fprintf(stderr,"Digest length mismatch, got %d expected %d\n",mdn,cn);
	exit(102);
	}

    if(memcmp(md,ciphertext,cn))
	{
	fprintf(stderr,"Digest mismatch\n");
	hexdump(stderr,"Got",md,cn);
	hexdump(stderr,"Expected",ciphertext,cn);
	exit(103);
	}

    printf("\n");

    return 1;
    }

int main(int argc,char **argv)
    {
    const char *szTestFile;
    FILE *f;

    if(argc != 2)
	{
	fprintf(stderr,"%s <test file>\n",argv[0]);
	exit(1);
	}

    szTestFile=argv[1];

    f=fopen(szTestFile,"r");
    if(!f)
	{
	perror(szTestFile);
	exit(2);
	}

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ENGINE_load_builtin_engines();

    for( ; ; )
	{
	char line[4096];
	char *p;
	char *cipher;
	unsigned char *iv,*key,*plaintext,*ciphertext;
	int kn,in,pn,cn;

	if(!fgets((char *)line,sizeof line,f))
	    break;
	if(line[0] == '#' || line[0] == '\n')
	    continue;
	p=line;
	cipher=(char*)ustrsep(&p,":");	
	key=ustrsep(&p,":");
	iv=ustrsep(&p,":");
	plaintext=ustrsep(&p,":");
	ciphertext=ustrsep(&p,"\n");

	kn=convert(key);
	in=convert(iv);
	pn=convert(plaintext);
	cn=convert(ciphertext);

	if(!test_cipher(cipher,key,kn,iv,in,plaintext,pn,ciphertext,cn)
	   && !test_digest(cipher,plaintext,pn,ciphertext,cn))
	    {
	    fprintf(stderr,"Can't find %s\n",cipher);
	    exit(3);
	    }
	}


    return 0;
    }
