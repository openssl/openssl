/* crypto/bn/bn_exp.c */
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
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"
#ifdef ATALLA
# include <alloca.h>
# include <atasi.h>
# include <assert.h>
# include <dlfcn.h>
#endif


#define TABLE_SIZE	32

/* slow but works */
int BN_mod_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
	{
	BIGNUM *t;
	int r=0;

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(m);

	BN_CTX_start(ctx);
	if ((t = BN_CTX_get(ctx)) == NULL) goto err;
	if (a == b)
		{ if (!BN_sqr(t,a,ctx)) goto err; }
	else
		{ if (!BN_mul(t,a,b,ctx)) goto err; }
	if (!BN_mod(ret,t,m,ctx)) goto err;
	r=1;
err:
	BN_CTX_end(ctx);
	return(r);
	}


/* this one works - simple but works */
int BN_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BN_CTX *ctx)
	{
	int i,bits,ret=0;
	BIGNUM *v,*rr;

	BN_CTX_start(ctx);
	if ((r == a) || (r == p))
		rr = BN_CTX_get(ctx);
	else
		rr = r;
	if ((v = BN_CTX_get(ctx)) == NULL) goto err;

	if (BN_copy(v,a) == NULL) goto err;
	bits=BN_num_bits(p);

	if (BN_is_odd(p))
		{ if (BN_copy(rr,a) == NULL) goto err; }
	else	{ if (!BN_one(rr)) goto err; }

	for (i=1; i<bits; i++)
		{
		if (!BN_sqr(v,v,ctx)) goto err;
		if (BN_is_bit_set(p,i))
			{
			if (!BN_mul(rr,rr,v,ctx)) goto err;
			}
		}
	ret=1;
err:
	if (r != rr) BN_copy(r,rr);
	BN_CTX_end(ctx);
	return(ret);
	}


#ifdef ATALLA

/*
 * This routine will dynamically check for the existance of an Atalla AXL-200
 * SSL accelerator module.  If one is found, the variable
 * asi_accelerator_present is set to 1 and the function pointers
 * ptr_ASI_xxxxxx above will be initialized to corresponding ASI API calls.
 */
typedef int tfnASI_GetPerformanceStatistics(int reset_flag,
					    unsigned int *ret_buf);
typedef int tfnASI_GetHardwareConfig(long card_num, unsigned int *ret_buf);
typedef int tfnASI_RSAPrivateKeyOpFn(RSAPrivateKey * rsaKey,
				     unsigned char *output,
				     unsigned char *input,
				     unsigned int modulus_len);

static tfnASI_GetHardwareConfig *ptr_ASI_GetHardwareConfig;
static tfnASI_RSAPrivateKeyOpFn *ptr_ASI_RSAPrivateKeyOpFn;
static tfnASI_GetPerformanceStatistics *ptr_ASI_GetPerformanceStatistics;
static int asi_accelerator_present;
static int tried_atalla;

void atalla_initialize_accelerator_handle(void)
	{
	void *dl_handle;
	int status;
	unsigned int config_buf[1024]; 
	static int tested;

	if(tested)
		return;

	tested=1;

	bzero((void *)config_buf, 1024);

	/*
	 * Check to see if the library is present on the system
	 */
	dl_handle = dlopen("atasi.so", RTLD_NOW);
	if (dl_handle == (void *) NULL)
		{
/*		printf("atasi.so library is not present on the system\n");
		printf("No HW acceleration available\n");*/
		return;
	        }

	/*
	 * The library is present.  Now we'll check to insure that the
	 * LDM is up and running. First we'll get the address of the
	 * function in the atasi library that we need to see if the
	 * LDM is operating.
	 */

	ptr_ASI_GetHardwareConfig =
	  (tfnASI_GetHardwareConfig *)dlsym(dl_handle,"ASI_GetHardwareConfig");

	if (ptr_ASI_GetHardwareConfig)
		{
		/*
		 * We found the call, now we'll get our config
		 * status.  If we get a non 0 result, the LDM is not
		 * running and we cannot use the Atalla ASI *
		 * library.
		 */
		status = (*ptr_ASI_GetHardwareConfig)(0L, config_buf);
		if (status != 0)
			{
			printf("atasi.so library is present but not initialized\n");
			printf("No HW acceleration available\n");
			return;
			}    
	        }
	else
		{
/*		printf("We found the library, but not the function. Very Strange!\n");*/
		return ;
	      	}

	/* 
	 * It looks like we have acceleration capabilities.  Load up the
	 * pointers to our ASI API calls.
	 */
	ptr_ASI_RSAPrivateKeyOpFn=
	  (tfnASI_RSAPrivateKeyOpFn *)dlsym(dl_handle, "ASI_RSAPrivateKeyOpFn");
	if (ptr_ASI_RSAPrivateKeyOpFn == NULL)
		{
/*		printf("We found the library, but no RSA function. Very Strange!\n");*/
		return;
	        }

	ptr_ASI_GetPerformanceStatistics =
	  (tfnASI_GetPerformanceStatistics *)dlsym(dl_handle, "ASI_GetPerformanceStatistics");
	if (ptr_ASI_GetPerformanceStatistics == NULL)
		{
/*		printf("We found the library, but no stat function. Very Strange!\n");*/
		return;
	      }

	/*
	 * Indicate that acceleration is available
	 */
	asi_accelerator_present = 1;

/*	printf("This system has acceleration!\n");*/

	return;
	}

/* make sure this only gets called once when bn_mod_exp calls bn_mod_exp_mont */
int BN_mod_exp_atalla(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m)
	{
	unsigned char *abin;
	unsigned char *pbin;
	unsigned char *mbin;
	unsigned char *rbin;
	int an,pn,mn,ret;
	RSAPrivateKey keydata;

	atalla_initialize_accelerator_handle();
	if(!asi_accelerator_present)
		return 0;


/* We should be able to run without size testing */
# define ASIZE	128
	an=BN_num_bytes(a);
	pn=BN_num_bytes(p);
	mn=BN_num_bytes(m);

	if(an <= ASIZE && pn <= ASIZE && mn <= ASIZE)
	    {
	    int size=mn;

	    assert(an <= mn);
	    abin=alloca(size);
	    memset(abin,'\0',mn);
	    BN_bn2bin(a,abin+size-an);

	    pbin=alloca(pn);
	    BN_bn2bin(p,pbin);

	    mbin=alloca(size);
	    memset(mbin,'\0',mn);
	    BN_bn2bin(m,mbin+size-mn);

	    rbin=alloca(size);

	    memset(&keydata,'\0',sizeof keydata);
	    keydata.privateExponent.data=pbin;
	    keydata.privateExponent.len=pn;
	    keydata.modulus.data=mbin;
	    keydata.modulus.len=size;

	    ret=(*ptr_ASI_RSAPrivateKeyOpFn)(&keydata,rbin,abin,keydata.modulus.len);
/*fprintf(stderr,"!%s\n",BN_bn2hex(a));*/
	    if(!ret)
	        {
		BN_bin2bn(rbin,keydata.modulus.len,r);
/*fprintf(stderr,"?%s\n",BN_bn2hex(r));*/
		return 1;
	        }
	    }
	return 0;
        }
#endif /* def ATALLA */


int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
	       BN_CTX *ctx)
	{
	int ret;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

#ifdef ATALLA
	if(BN_mod_exp_atalla(r,a,p,m))
	    return 1;
/* If it fails, try the other methods (but don't try atalla again) */
	tried_atalla=1;
#endif

#ifdef MONT_MUL_MOD
	/* I have finally been able to take out this pre-condition of
	 * the top bit being set.  It was caused by an error in BN_div
	 * with negatives.  There was also another problem when for a^b%m
	 * a >= m.  eay 07-May-97 */
/*	if ((m->d[m->top-1]&BN_TBIT) && BN_is_odd(m)) */

	if (BN_is_odd(m))
		{
		if (a->top == 1)
			{
			BN_ULONG A = a->d[0];
			ret=BN_mod_exp_mont_word(r,A,p,m,ctx,NULL);
			}
		else
			ret=BN_mod_exp_mont(r,a,p,m,ctx,NULL);
		}
	else
#endif
#ifdef RECP_MUL_MOD
		{ ret=BN_mod_exp_recp(r,a,p,m,ctx); }
#else
		{ ret=BN_mod_exp_simple(r,a,p,m,ctx); }
#endif

#ifdef ATALLA
	tried_atalla=0;
#endif

	return(ret);
	}


int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue;
	int start=1,ts=0;
	BIGNUM *aa;
	BIGNUM val[TABLE_SIZE];
	BN_RECP_CTX recp;

	bits=BN_num_bits(p);

	if (bits == 0)
		{
		BN_one(r);
		return(1);
		}

	BN_CTX_start(ctx);
	if ((aa = BN_CTX_get(ctx)) == NULL) goto err;

	BN_RECP_CTX_init(&recp);
	if (BN_RECP_CTX_set(&recp,m,ctx) <= 0) goto err;

	BN_init(&(val[0]));
	ts=1;

	if (!BN_mod(&(val[0]),a,m,ctx)) goto err;		/* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1)
		{
		if (!BN_mod_mul_reciprocal(aa,&(val[0]),&(val[0]),&recp,ctx))
			goto err;				/* 2 */
		j=1<<(window-1);
		for (i=1; i<j; i++)
			{
			BN_init(&val[i]);
			if (!BN_mod_mul_reciprocal(&(val[i]),&(val[i-1]),aa,&recp,ctx))
				goto err;
			}
		ts=i;
		}
		
	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

	if (!BN_one(r)) goto err;

	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				if (!BN_mod_mul_reciprocal(r,r,r,&recp,ctx))
				goto err;
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul_reciprocal(r,r,r,&recp,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_reciprocal(r,r,&(val[wvalue>>1]),&recp,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	ret=1;
err:
	BN_CTX_end(ctx);
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	BN_RECP_CTX_free(&recp);
	return(ret);
	}


int BN_mod_exp_mont(BIGNUM *rr, BIGNUM *a, const BIGNUM *p,
		    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue;
	int start=1,ts=0;
	BIGNUM *d,*r;
	BIGNUM *aa;
	BIGNUM val[TABLE_SIZE];
	BN_MONT_CTX *mont=NULL;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

#ifdef ATALLA
	if(!tried_atalla && BN_mod_exp_atalla(rr,a,p,m))
	    return 1;
/* If it fails, try the other methods */
#endif

	if (!(m->d[0] & 1))
		{
		BNerr(BN_F_BN_MOD_EXP_MONT,BN_R_CALLED_WITH_EVEN_MODULUS);
		return(0);
		}
	bits=BN_num_bits(p);
	if (bits == 0)
		{
		BN_one(rr);
		return(1);
		}
	BN_CTX_start(ctx);
	d = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	if (d == NULL || r == NULL) goto err;

	/* If this is not done, things will break in the montgomery
	 * part */

	if (in_mont != NULL)
		mont=in_mont;
	else
		{
		if ((mont=BN_MONT_CTX_new()) == NULL) goto err;
		if (!BN_MONT_CTX_set(mont,m,ctx)) goto err;
		}

	BN_init(&val[0]);
	ts=1;
	if (BN_ucmp(a,m) >= 0)
		{
		if (!BN_mod(&(val[0]),a,m,ctx))
			goto err;
		aa= &(val[0]);
		}
	else
		aa=a;
	if (!BN_to_montgomery(&(val[0]),aa,mont,ctx)) goto err; /* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1)
		{
		if (!BN_mod_mul_montgomery(d,&(val[0]),&(val[0]),mont,ctx)) goto err; /* 2 */
		j=1<<(window-1);
		for (i=1; i<j; i++)
			{
			BN_init(&(val[i]));
			if (!BN_mod_mul_montgomery(&(val[i]),&(val[i-1]),d,mont,ctx))
				goto err;
			}
		ts=i;
		}

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

	if (!BN_to_montgomery(r,BN_value_one(),mont,ctx)) goto err;
	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
				goto err;
				}
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_montgomery(r,r,&(val[wvalue>>1]),mont,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	if (!BN_from_montgomery(rr,r,mont,ctx)) goto err;
	ret=1;
err:
	if ((in_mont == NULL) && (mont != NULL)) BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	return(ret);
	}

int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	BN_MONT_CTX *mont = NULL;
	int b, bits, ret=0;
	int r_is_one;
	BN_ULONG w, next_w;
	BIGNUM *d, *r, *t;
	BIGNUM *swap_tmp;
#define BN_MOD_MUL_WORD(r, w, m) \
		(BN_mul_word(r, (w)) && \
		(/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
			(BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
		/* BN_MOD_MUL_WORD is only used with 'w' large,
		  * so the BN_ucmp test is probably more overhead
		  * than always using BN_mod (which uses BN_copy if
		  * a similar test returns true). */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
		(BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

	bn_check_top(p);
	bn_check_top(m);

	if (!(m->d[0] & 1))
		{
		BNerr(BN_F_BN_MOD_EXP_MONT_WORD,BN_R_CALLED_WITH_EVEN_MODULUS);
		return(0);
		}
	bits = BN_num_bits(p);
	if (bits == 0)
		{
		BN_one(rr);
		return(1);
		}
	BN_CTX_start(ctx);
	d = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	t = BN_CTX_get(ctx);
	if (d == NULL || r == NULL || t == NULL) goto err;

#ifdef ATALLA
	if (!tried_atalla)
		{
		BN_set_word(t, a);
		if (BN_mod_exp_atalla(rr, t, p, m))
			{
			BN_CTX_end(ctx);
			return 1;
			}
		}
/* If it fails, try the other methods */
#endif

	if (in_mont != NULL)
		mont=in_mont;
	else
		{
		if ((mont = BN_MONT_CTX_new()) == NULL) goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx)) goto err;
		}

	r_is_one = 1; /* except for Montgomery factor */

	/* bits-1 >= 0 */

	/* The result is accumulated in the product r*w. */
	w = a; /* bit 'bits-1' of 'p' is always set */
	for (b = bits-2; b >= 0; b--)
		{
		/* First, square r*w. */
		next_w = w*w;
		if ((next_w/w) != w) /* overflow */
			{
			if (r_is_one)
				{
				if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) goto err;
				r_is_one = 0;
				}
			else
				{
				if (!BN_MOD_MUL_WORD(r, w, m)) goto err;
				}
			next_w = 1;
			}
		w = next_w;
		if (!r_is_one)
			{
			if (!BN_mod_mul_montgomery(r, r, r, mont, ctx)) goto err;
			}

		/* Second, multiply r*w by 'a' if exponent bit is set. */
		if (BN_is_bit_set(p, b))
			{
			next_w = w*a;
			if ((next_w/a) != w) /* overflow */
				{
				if (r_is_one)
					{
					if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) goto err;
					r_is_one = 0;
					}
				else
					{
					if (!BN_MOD_MUL_WORD(r, w, m)) goto err;
					}
				next_w = a;
				}
			w = next_w;
			}
		}

	/* Finally, set r:=r*w. */
	if (w != 1)
		{
		if (r_is_one)
			{
			if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) goto err;
			r_is_one = 0;
			}
		else
			{
			if (!BN_MOD_MUL_WORD(r, w, m)) goto err;
			}
		}

	if (r_is_one) /* can happen only if a == 1*/
		{
		if (!BN_one(rr)) goto err;
		}
	else
		{
		if (!BN_from_montgomery(rr, r, mont, ctx)) goto err;
		}
	ret = 1;
err:
	if ((in_mont == NULL) && (mont != NULL)) BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	return(ret);
	}


/* The old fallback, simple version :-) */
int BN_mod_exp_simple(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m,
	     BN_CTX *ctx)
	{
	int i,j,bits,ret=0,wstart,wend,window,wvalue,ts=0;
	int start=1;
	BIGNUM *d;
	BIGNUM val[TABLE_SIZE];

	bits=BN_num_bits(p);

	if (bits == 0)
		{
		BN_one(r);
		return(1);
		}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL) goto err;

	BN_init(&(val[0]));
	ts=1;
	if (!BN_mod(&(val[0]),a,m,ctx)) goto err;		/* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1)
		{
		if (!BN_mod_mul(d,&(val[0]),&(val[0]),m,ctx))
			goto err;				/* 2 */
		j=1<<(window-1);
		for (i=1; i<j; i++)
			{
			BN_init(&(val[i]));
			if (!BN_mod_mul(&(val[i]),&(val[i-1]),d,m,ctx))
				goto err;
			}
		ts=i;
		}

	start=1;	/* This is used to avoid multiplication etc
			 * when there is only the value '1' in the
			 * buffer. */
	wvalue=0;	/* The 'value' of the window */
	wstart=bits-1;	/* The top bit of the window */
	wend=0;		/* The bottom bit of the window */

	if (!BN_one(r)) goto err;

	for (;;)
		{
		if (BN_is_bit_set(p,wstart) == 0)
			{
			if (!start)
				if (!BN_mod_mul(r,r,r,m,ctx))
				goto err;
			if (wstart == 0) break;
			wstart--;
			continue;
			}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j=wstart;
		wvalue=1;
		wend=0;
		for (i=1; i<window; i++)
			{
			if (wstart-i < 0) break;
			if (BN_is_bit_set(p,wstart-i))
				{
				wvalue<<=(i-wend);
				wvalue|=1;
				wend=i;
				}
			}

		/* wend is the size of the current window */
		j=wend+1;
		/* add the 'bytes above' */
		if (!start)
			for (i=0; i<j; i++)
				{
				if (!BN_mod_mul(r,r,r,m,ctx))
					goto err;
				}
		
		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul(r,r,&(val[wvalue>>1]),m,ctx))
			goto err;

		/* move the 'window' down further */
		wstart-=wend+1;
		wvalue=0;
		start=0;
		if (wstart < 0) break;
		}
	ret=1;
err:
	BN_CTX_end(ctx);
	for (i=0; i<ts; i++)
		BN_clear_free(&(val[i]));
	return(ret);
	}

