/* crypto/bn/expspeed.c */
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

/* most of this code has been pilfered from my libdes speed.c program */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/tmdiff.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define DEFAULT_SIZE	512
#define DEFAULT_TIME	3

int verbose=1;

typedef struct parms_st
	{
	char *name;
	void (*func)();
	BIGNUM r;
	BIGNUM a;
	BIGNUM b;
	BIGNUM c;
	BIGNUM low;
	BN_CTX *ctx;
	BN_MONT_CTX *mont;
	int w;
	} PARMS;

void do_mul_exp(int num,PARMS *p);
void do_mul(int num,PARMS *p);
void do_sqr(int num,PARMS *p);
void do_mul_low(int num,PARMS *p);
void do_mul_high(int num,PARMS *p);
void do_from_montgomery(int num,PARMS *p);
int time_it(int sec, PARMS *p);
void do_it(int sec, PARMS *p);

#define P_EXP	1
#define P_MUL	2
#define P_SQR	3
#define P_MULL	4
#define P_MULH	5
#define P_MRED	6

int main(int argc, char **argv)
	{
	PARMS p;
	BN_MONT_CTX *mont;
	int size=0,num;
	char *name;
	int type=P_EXP;

	mont=BN_MONT_CTX_new();
	p.mont=NULL;
	p.ctx=BN_CTX_new();
	BN_init(&p.r);
	BN_init(&p.a);
	BN_init(&p.b);
	BN_init(&p.c);
	BN_init(&p.low);
	p.w=0;

	for (;;)
		{
		if (argc > 1)
			{
			if (argv[1][0] == '-')
				{
				switch(argv[1][1])
					{
				case 'e': type=P_EXP; break;
				case 'm': type=P_MUL; break;
				case 's': type=P_SQR; break;
				case 'l': type=P_MULL; break;
				case 'h': type=P_MULH; break;
				case 'r': type=P_MRED; break;
				default:
					fprintf(stderr,"options: -[emslhr]\n");
					exit(1);
					}
				}
			else
				{
				size=atoi(argv[1]);
				}
			argc--;
			argv++;
			}
		else
			break;
		}
	if (size == 0)
		size=DEFAULT_SIZE;

	printf("bit size:%5d\n",size);

	BN_rand(&p.a,size,1,0);
	BN_rand(&p.b,size,1,0);
	BN_rand(&p.c,size,1,1);
	BN_mod(&p.a,&p.a,&p.c,p.ctx);
	BN_mod(&p.b,&p.b,&p.c,p.ctx);
	p.w=(p.a.top+1)/2;

	BN_mul(&p.low,&p.a,&p.b,p.ctx);
	p.low.top=p.a.top;
	
	switch(type)
		{
	case P_EXP:
		p.name="r=a^b%c";
		p.func=do_mul_exp;
		p.mont=mont;
		break;
	case P_MUL:
		p.name="r=a*b";
		p.func=do_mul;
		break;
	case P_SQR:
		p.name="r=a*a";
		p.func=do_sqr;
		break;
	case P_MULL:
		p.name="r=low(a*b)";
		p.func=do_mul_low;
		break;
	case P_MULH:
		p.name="r=high(a*b)";
		p.func=do_mul_high;
		break;
	case P_MRED:
		p.name="r=montgomery_reduction(a)";
		p.func=do_from_montgomery;
		p.mont=mont;
		break;
	default:
		fprintf(stderr,"options: -[emslhr]\n");
		exit(1);
		}

	num=time_it(DEFAULT_TIME,&p);
	do_it(num,&p);
	}

void do_it(int num, PARMS *p)
	{
	char *start,*end;
	int i,j,number;
	double d;

	start=ms_time_new();
	end=ms_time_new();

	number=BN_num_bits_word((BN_ULONG)BN_num_bits(&(p->c)))-
		BN_num_bits_word(BN_BITS2)+2;
	for (i=number-1; i >=0; i--)
		{
		if (i == 1) continue;
		BN_set_params(i,i,i,1);
		if (p->mont != NULL)
			BN_MONT_CTX_set(p->mont,&(p->c),p->ctx);

		printf("Timing %5d (%2d bit) %2d %2d %2d %2d :",
			(1<<i)*BN_BITS2,i,
				BN_get_params(0),
				BN_get_params(1),
				BN_get_params(2),
				BN_get_params(3));
		fflush(stdout);

		ms_time_get(start);
		p->func(num,p);
		ms_time_get(end);
		d=ms_time_diff(start,end);
		printf("%6.6f sec, or %d in %.4f seconds\n",
			(double)d/num,num,d);
		}
	}

int time_it(int sec, PARMS *p)
	{
	char *start,*end;
	int i,j;
	double d;

	if (p->mont != NULL)
		BN_MONT_CTX_set(p->mont,&(p->c),p->ctx);

	start=ms_time_new();
	end=ms_time_new();

	i=1;
	for (;;)
		{
		if (verbose)
			printf("timing %s for %d interations\n",p->name,i);

		ms_time_get(start);
		p->func(i,p);
		ms_time_get(end);
		d=ms_time_diff(start,end);

		if 	(d < 0.01) i*=100;
		else if (d < 0.1 ) i*=10;
		else if (d > (double)sec) break;
		else
			{
			i=(int)(1.0*i*sec/d);
			break;
			}
		}
	if (verbose)
		printf("using %d interations\n",i);
	return(i);
	}

void do_mul_exp(int num, PARMS *p)
	{
	int i;

	for (i=0; i<num; i++)
		BN_mod_exp_mont(&(p->r),&(p->a),&(p->b),&(p->c),
			p->ctx,p->mont);
	}

void do_mul(int num, PARMS *p)
	{
	int i;

	for (i=0; i<num; i++)
		BN_mul(&(p->r),&(p->a),&(p->b),p->ctx);
	}

void do_sqr(int num, PARMS *p)
	{
	int i;

	for (i=0; i<num; i++)
			BN_sqr(&(p->r),&(p->a),p->ctx);
	}

void do_mul_low(int num, PARMS *p)
	{
	int i;
	
	for (i=0; i<num; i++)
		BN_mul_low(&(p->r),&(p->a),&(p->b),p->w,p->ctx);
	}

void do_mul_high(int num, PARMS *p)
	{
	int i;

	for (i=0; i<num; i++)
		BN_mul_low(&(p->r),&(p->a),&(p->b),&(p->low),p->w,p->ctx);
	}

void do_from_montgomery(int num, PARMS *p)
	{
	int i;
	
	for (i=0; i<num; i++)
		BN_from_montgomery(&(p->r),&(p->a),p->mont,p->ctx);
	}

