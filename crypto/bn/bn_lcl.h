/* crypto/bn/bn_lcl.h */
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

#ifndef HEADER_BN_LCL_H
#define HEADER_BN_LCL_H

#include <openssl/bn.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Pentium pro 16,16,16,32,64 */
/* Alpha       16,16,16,16.64 */
#define BN_MULL_SIZE_NORMAL			(16) /* 32 */
#define BN_MUL_RECURSIVE_SIZE_NORMAL		(16) /* 32 less than */
#define BN_SQR_RECURSIVE_SIZE_NORMAL		(16) /* 32 */
#define BN_MUL_LOW_RECURSIVE_SIZE_NORMAL	(32) /* 32 */
#define BN_MONT_CTX_SET_SIZE_WORD		(64) /* 32 */

#if 0
#ifndef BN_MUL_COMBA
/* #define bn_mul_comba8(r,a,b)	bn_mul_normal(r,a,8,b,8) */
/* #define bn_mul_comba4(r,a,b)	bn_mul_normal(r,a,4,b,4) */
#endif

#ifndef BN_SQR_COMBA
/* This is probably faster than using the C code - I need to check */
#define bn_sqr_comba8(r,a)	bn_mul_normal(r,a,8,a,8)
#define bn_sqr_comba4(r,a)	bn_mul_normal(r,a,4,a,4)
#endif
#endif

/*************************************************************
 * Using the long long type
 */
#define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)

/* These are used for internal error checking and are not normally used */
#ifdef BN_DEBUG
#define bn_check_top(a) \
	{ if (((a)->top < 0) || ((a)->top > (a)->max)) \
		{ char *nullp=NULL; *nullp='z'; } }
#define bn_check_num(a) if ((a) < 0) { char *nullp=NULL; *nullp='z'; }
#else
#define bn_check_top(a)
#define bn_check_num(a)
#endif

/* This macro is to add extra stuff for development checking */
#ifdef BN_DEBUG
#define	bn_set_max(r) ((r)->max=(r)->top,BN_set_flags((r),BN_FLG_STATIC_DATA))
#else
#define	bn_set_max(r)
#endif

/* These macros are used to 'take' a section of a bignum for read only use */
#define bn_set_low(r,a,n) \
	{ \
	(r)->top=((a)->top > (n))?(n):(a)->top; \
	(r)->d=(a)->d; \
	(r)->neg=(a)->neg; \
	(r)->flags|=BN_FLG_STATIC_DATA; \
	bn_set_max(r); \
	}

#define bn_set_high(r,a,n) \
	{ \
	if ((a)->top > (n)) \
		{ \
		(r)->top=(a)->top-n; \
		(r)->d= &((a)->d[n]); \
		} \
	else \
		(r)->top=0; \
	(r)->neg=(a)->neg; \
	(r)->flags|=BN_FLG_STATIC_DATA; \
	bn_set_max(r); \
	}

/* #define bn_expand(n,b) ((((b)/BN_BITS2) <= (n)->max)?(n):bn_expand2((n),(b))) */

#ifdef BN_LLONG
#define mul_add(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (r) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}

#define mul(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}

#else
/*************************************************************
 * No long long type
 */

#define LBITS(a)	((a)&BN_MASK2l)
#define HBITS(a)	(((a)>>BN_BITS4)&BN_MASK2l)
#define	L2HBITS(a)	((BN_ULONG)((a)&BN_MASK2l)<<BN_BITS4)

#define LLBITS(a)	((a)&BN_MASKl)
#define LHBITS(a)	(((a)>>BN_BITS2)&BN_MASKl)
#define	LL2HBITS(a)	((BN_ULLONG)((a)&BN_MASKl)<<BN_BITS2)

#define mul64(l,h,bl,bh) \
	{ \
	BN_ULONG m,m1,lt,ht; \
 \
	lt=l; \
	ht=h; \
	m =(bh)*(lt); \
	lt=(bl)*(lt); \
	m1=(bl)*(ht); \
	ht =(bh)*(ht); \
	m=(m+m1)&BN_MASK2; if (m < m1) ht+=L2HBITS(1L); \
	ht+=HBITS(m); \
	m1=L2HBITS(m); \
	lt=(lt+m1)&BN_MASK2; if (lt < m1) ht++; \
	(l)=lt; \
	(h)=ht; \
	}

#define sqr64(lo,ho,in) \
	{ \
	BN_ULONG l,h,m; \
 \
	h=(in); \
	l=LBITS(h); \
	h=HBITS(h); \
	m =(l)*(h); \
	l*=l; \
	h*=h; \
	h+=(m&BN_MASK2h1)>>(BN_BITS4-1); \
	m =(m&BN_MASK2l)<<(BN_BITS4+1); \
	l=(l+m)&BN_MASK2; if (l < m) h++; \
	(lo)=l; \
	(ho)=h; \
	}

#define mul_add(r,a,bl,bh,c) { \
	BN_ULONG l,h; \
 \
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
 \
	/* non-multiply part */ \
	l=(l+(c))&BN_MASK2; if (l < (c)) h++; \
	(c)=(r); \
	l=(l+(c))&BN_MASK2; if (l < (c)) h++; \
	(c)=h&BN_MASK2; \
	(r)=l; \
	}

#define mul(r,a,bl,bh,c) { \
	BN_ULONG l,h; \
 \
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
 \
	/* non-multiply part */ \
	l+=(c); if ((l&BN_MASK2) < (c)) h++; \
	(c)=h&BN_MASK2; \
	(r)=l&BN_MASK2; \
	}

#endif

OPENSSL_EXTERN int bn_limit_bits;
OPENSSL_EXTERN int bn_limit_num;        /* (1<<bn_limit_bits) */
/* Recursive 'low' limit */
OPENSSL_EXTERN int bn_limit_bits_low;
OPENSSL_EXTERN int bn_limit_num_low;    /* (1<<bn_limit_bits_low) */
/* Do modified 'high' part calculation' */
OPENSSL_EXTERN int bn_limit_bits_high;
OPENSSL_EXTERN int bn_limit_num_high;   /* (1<<bn_limit_bits_high) */
OPENSSL_EXTERN int bn_limit_bits_mont;
OPENSSL_EXTERN int bn_limit_num_mont;   /* (1<<bn_limit_bits_mont) */

BIGNUM *bn_expand2(BIGNUM *b, int bits);

void bn_mul_normal(BN_ULONG *r,BN_ULONG *a,int na,BN_ULONG *b,int nb);
void bn_mul_comba8(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
void bn_mul_comba4(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
void bn_sqr_normal(BN_ULONG *r, BN_ULONG *a, int n, BN_ULONG *tmp);
void bn_sqr_comba8(BN_ULONG *r,BN_ULONG *a);
void bn_sqr_comba4(BN_ULONG *r,BN_ULONG *a);
int bn_cmp_words(BN_ULONG *a,BN_ULONG *b,int n);
void bn_mul_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,int n2,BN_ULONG *t);
void bn_mul_part_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,
	int tn, int n,BN_ULONG *t);
void bn_sqr_recursive(BN_ULONG *r,BN_ULONG *a, int n2, BN_ULONG *t);
void bn_mul_low_normal(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b, int n);
void bn_mul_low_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,int n2,
	BN_ULONG *t);
void bn_mul_high(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,BN_ULONG *l,int n2,
	BN_ULONG *t);

#ifdef  __cplusplus
}
#endif

#endif
