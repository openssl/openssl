/* crypto/bn/bntest.c */
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
#include <stdlib.h>
#include <string.h>
#include "e_os.h"
#include "bio.h"
#include "bn.h"
#include "rand.h"
#include "x509.h"
#include "err.h"

#ifdef WINDOWS
#include "../bio/bss_file.c"
#endif

#ifndef NOPROTO
int test_add (BIO *bp);
int test_sub (BIO *bp);
int test_lshift1 (BIO *bp);
int test_lshift (BIO *bp);
int test_rshift1 (BIO *bp);
int test_rshift (BIO *bp);
int test_div (BIO *bp,BN_CTX *ctx);
int test_mul (BIO *bp);
int test_sqr (BIO *bp,BN_CTX *ctx);
int test_mont (BIO *bp,BN_CTX *ctx);
int test_mod (BIO *bp,BN_CTX *ctx);
int test_mod_mul (BIO *bp,BN_CTX *ctx);
int test_mod_exp (BIO *bp,BN_CTX *ctx);
int rand_neg(void);
#else
int test_add ();
int test_sub ();
int test_lshift1 ();
int test_lshift ();
int test_rshift1 ();
int test_rshift ();
int test_div ();
int test_mul ();
int test_sqr ();
int test_mont ();
int test_mod ();
int test_mod_mul ();
int test_mod_exp ();
int rand_neg();
#endif

static int results=0;

#ifdef NO_STDIO
#define APPS_WIN16
#include "bss_file.c"
#endif

int main(argc,argv)
int argc;
char *argv[];
	{
	BN_CTX *ctx;
	BIO *out;
	char *outfile=NULL;

	srand((unsigned int)time(NULL));

	argc--;
	argv++;
	while (argc >= 1)
		{
		if (strcmp(*argv,"-results") == 0)
			results=1;
		else if (strcmp(*argv,"-out") == 0)
			{
			if (--argc < 1) break;
			outfile= *(++argv);
			}
		argc--;
		argv++;
		}


	ctx=BN_CTX_new();
	if (ctx == NULL) exit(1);

	out=BIO_new(BIO_s_file());
	if (out == NULL) exit(1);
	if (outfile == NULL)
		{
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
		}
	else
		{
		if (!BIO_write_filename(out,outfile))
			{
			perror(outfile);
			exit(1);
			}
		}

	if (!results)
		BIO_puts(out,"obase=16\nibase=16\n");

	fprintf(stderr,"test BN_add\n");
	if (!test_add(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_sub\n");
	if (!test_sub(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_lshift1\n");
	if (!test_lshift1(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_lshift\n");
	if (!test_lshift(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_rshift1\n");
	if (!test_rshift1(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_rshift\n");
	if (!test_rshift(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_sqr\n");
	if (!test_sqr(out,ctx)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_mul\n");
	if (!test_mul(out)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_div\n");
	if (!test_div(out,ctx)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_mod\n");
	if (!test_mod(out,ctx)) goto err;
	fflush(stdout);

	fprintf(stderr,"test BN_mod_mul\n");
	if (!test_mod_mul(out,ctx)) goto err;
	fflush(stdout);

/*
	fprintf(stderr,"test BN_mont\n");
	if (!test_mont(out,ctx)) goto err;
	fflush(stdout);
*/
	fprintf(stderr,"test BN_mod_exp\n");
	if (!test_mod_exp(out,ctx)) goto err;
	fflush(stdout);

/**/
	exit(0);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(out);
	exit(1);
	return(1);
	}

int test_add(bp)
BIO *bp;
	{
	BIGNUM *a,*b,*c;
	int i;
	int j;

	a=BN_new();
	b=BN_new();
	c=BN_new();

	BN_rand(a,512,0,0);
	for (i=0; i<100; i++)
		{
		BN_rand(b,450+i,0,0);
		a->neg=rand_neg();
		b->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<10000; j++)
				BN_add(c,a,b);
		BN_add(c,a,b);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," + ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_sub(bp)
BIO *bp;
	{
	BIGNUM *a,*b,*c;
	int i;
	int j;

	a=BN_new();
	b=BN_new();
	c=BN_new();

	BN_rand(a,512,0,0);
	for (i=0; i<100; i++)
		{
		BN_rand(b,400+i,0,0);
		a->neg=rand_neg();
		b->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<10000; j++)
				BN_sub(c,a,b);
		BN_sub(c,a,b);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," - ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_div(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*b,*c,*d;
	int i;
	int j;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	d=BN_new();

	BN_rand(a,400,0,0);
	for (i=0; i<100; i++)
		{
		BN_rand(b,50+i,0,0);
		a->neg=rand_neg();
		b->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<100; j++)
				BN_div(d,c,a,b,ctx);
		BN_div(d,c,a,b,ctx);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," / ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,d);
			BIO_puts(bp,"\n");

			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," % ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(d);
	return(1);
	}

int test_mul(bp)
BIO *bp;
	{
	BIGNUM *a,*b,*c;
	int i;
	int j;

	a=BN_new();
	b=BN_new();
	c=BN_new();

	BN_rand(a,200,0,0);
	for (i=0; i<100; i++)
		{
		BN_rand(b,250+i,0,0);
		a->neg=rand_neg();
		b->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<100; j++)
				BN_mul(c,a,b);
		BN_mul(c,a,b);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," * ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_sqr(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*c;
	int i;
	int j;

	a=BN_new();
	c=BN_new();

	for (i=0; i<40; i++)
		{
		BN_rand(a,40+i*10,0,0);
		a->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<100; j++)
				BN_sqr(c,a,ctx);
		BN_sqr(c,a,ctx);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," * ");
				BN_print(bp,a);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(c);
	return(1);
	}

int test_mont(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*b,*c,*A,*B;
	BIGNUM *n;
	int i;
	int j;
	BN_MONT_CTX *mont;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	A=BN_new();
	B=BN_new();
	n=BN_new();

	mont=BN_MONT_CTX_new();

	BN_rand(a,100,0,0); /**/
	BN_rand(b,100,0,0); /**/
	for (i=0; i<10; i++)
		{
		BN_rand(n,(100%BN_BITS2+1)*BN_BITS2*i*BN_BITS2,0,1); /**/
		BN_MONT_CTX_set(mont,n,ctx);

		BN_to_montgomery(A,a,mont,ctx);
		BN_to_montgomery(B,b,mont,ctx);

		if (bp == NULL)
			for (j=0; j<100; j++)
				BN_mod_mul_montgomery(c,A,B,mont,ctx);/**/
		BN_mod_mul_montgomery(c,A,B,mont,ctx);/**/
		BN_from_montgomery(A,c,mont,ctx);/**/
		if (bp != NULL)
			{
			if (!results)
				{
#ifdef undef
fprintf(stderr,"%d * %d %% %d\n",
BN_num_bits(a),
BN_num_bits(b),
BN_num_bits(mont->N));
#endif
				BN_print(bp,a);
				BIO_puts(bp," * ");
				BN_print(bp,b);
				BIO_puts(bp," % ");
				BN_print(bp,mont->N);
				BIO_puts(bp," - ");
				}
			BN_print(bp,A);
			BIO_puts(bp,"\n");
			}
		}
	BN_MONT_CTX_free(mont);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_mod(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*b,*c;
	int i;
	int j;

	a=BN_new();
	b=BN_new();
	c=BN_new();

	BN_rand(a,1024,0,0); /**/
	for (i=0; i<20; i++)
		{
		BN_rand(b,450+i*10,0,0); /**/
		a->neg=rand_neg();
		b->neg=rand_neg();
		if (bp == NULL)
			for (j=0; j<100; j++)
				BN_mod(c,a,b,ctx);/**/
		BN_mod(c,a,b,ctx);/**/
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," % ");
				BN_print(bp,b);
				BIO_puts(bp," - ");
				}
			BN_print(bp,c);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_mod_mul(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*b,*c,*d,*e;
	int i;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	d=BN_new();
	e=BN_new();

	BN_rand(c,1024,0,0); /**/
	for (i=0; i<10; i++)
		{
		BN_rand(a,475+i*10,0,0); /**/
		BN_rand(b,425+i*10,0,0); /**/
		a->neg=rand_neg();
		b->neg=rand_neg();
	/*	if (bp == NULL)
			for (j=0; j<100; j++)
				BN_mod_mul(d,a,b,c,ctx);*/ /**/

		if (!BN_mod_mul(e,a,b,c,ctx))
			{
			unsigned long l;

			while ((l=ERR_get_error()))
				fprintf(stderr,"ERROR:%s\n",
					ERR_error_string(l,NULL));
			exit(1);
			}
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," * ");
				BN_print(bp,b);
				BIO_puts(bp," % ");
				BN_print(bp,c);
				BIO_puts(bp," - ");
				}
			BN_print(bp,e);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(d);
	BN_free(e);
	return(1);
	}

int test_mod_exp(bp,ctx)
BIO *bp;
BN_CTX *ctx;
	{
	BIGNUM *a,*b,*c,*d,*e;
	int i;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	d=BN_new();
	e=BN_new();

	BN_rand(c,30,0,1); /* must be odd for montgomery */
	for (i=0; i<6; i++)
		{
		BN_rand(a,20+i*5,0,0); /**/
		BN_rand(b,2+i,0,0); /**/

		if (!BN_mod_exp(d,a,b,c,ctx))
			return(00);

		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," ^ ");
				BN_print(bp,b);
				BIO_puts(bp," % ");
				BN_print(bp,c);
				BIO_puts(bp," - ");
				}
			BN_print(bp,d);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(d);
	BN_free(e);
	return(1);
	}

int test_lshift(bp)
BIO *bp;
	{
	BIGNUM *a,*b,*c;
	int i;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	BN_one(c);

	BN_rand(a,200,0,0); /**/
	a->neg=rand_neg();
	for (i=0; i<70; i++)
		{
		BN_lshift(b,a,i+1);
		BN_add(c,c,c);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," * ");
				BN_print(bp,c);
				BIO_puts(bp," - ");
				}
			BN_print(bp,b);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_lshift1(bp)
BIO *bp;
	{
	BIGNUM *a,*b;
	int i;

	a=BN_new();
	b=BN_new();

	BN_rand(a,200,0,0); /**/
	a->neg=rand_neg();
	for (i=0; i<70; i++)
		{
		BN_lshift1(b,a);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," * 2");
				BIO_puts(bp," - ");
				}
			BN_print(bp,b);
			BIO_puts(bp,"\n");
			}
		BN_copy(a,b);
		}
	BN_free(a);
	BN_free(b);
	return(1);
	}

int test_rshift(bp)
BIO *bp;
	{
	BIGNUM *a,*b,*c;
	int i;

	a=BN_new();
	b=BN_new();
	c=BN_new();
	BN_one(c);

	BN_rand(a,200,0,0); /**/
	a->neg=rand_neg();
	for (i=0; i<70; i++)
		{
		BN_rshift(b,a,i+1);
		BN_add(c,c,c);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," / ");
				BN_print(bp,c);
				BIO_puts(bp," - ");
				}
			BN_print(bp,b);
			BIO_puts(bp,"\n");
			}
		}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	return(1);
	}

int test_rshift1(bp)
BIO *bp;
	{
	BIGNUM *a,*b;
	int i;

	a=BN_new();
	b=BN_new();

	BN_rand(a,200,0,0); /**/
	a->neg=rand_neg();
	for (i=0; i<70; i++)
		{
		BN_rshift1(b,a);
		if (bp != NULL)
			{
			if (!results)
				{
				BN_print(bp,a);
				BIO_puts(bp," / 2");
				BIO_puts(bp," - ");
				}
			BN_print(bp,b);
			BIO_puts(bp,"\n");
			}
		BN_copy(a,b);
		}
	BN_free(a);
	BN_free(b);
	return(1);
	}

int rand_neg()
	{
	static unsigned int neg=0;
	static int sign[8]={0,0,0,1,1,0,1,1};

	return(sign[(neg++)%8]);
	}
