/* crypto/bn/bn_mulw.c */
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
#include "bn_lcl.h"

#ifdef BN_LLONG 

BN_ULONG bn_mul_add_words(rp,ap,num,w)
BN_ULONG *rp,*ap;
int num;
BN_ULONG w;
	{
	BN_ULONG c1=0;

	for (;;)
		{
		mul_add(rp[0],ap[0],w,c1);
		if (--num == 0) break;
		mul_add(rp[1],ap[1],w,c1);
		if (--num == 0) break;
		mul_add(rp[2],ap[2],w,c1);
		if (--num == 0) break;
		mul_add(rp[3],ap[3],w,c1);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
		}
	
	return(c1);
	} 

BN_ULONG bn_mul_words(rp,ap,num,w)
BN_ULONG *rp,*ap;
int num;
BN_ULONG w;
	{
	BN_ULONG c1=0;

	for (;;)
		{
		mul(rp[0],ap[0],w,c1);
		if (--num == 0) break;
		mul(rp[1],ap[1],w,c1);
		if (--num == 0) break;
		mul(rp[2],ap[2],w,c1);
		if (--num == 0) break;
		mul(rp[3],ap[3],w,c1);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
		}
	return(c1);
	} 

void bn_sqr_words(r,a,n)
BN_ULONG *r,*a;
int n;
        {
	for (;;)
		{
		BN_ULLONG t;

		t=(BN_ULLONG)(a[0])*(a[0]);
		r[0]=Lw(t); r[1]=Hw(t);
		if (--n == 0) break;

		t=(BN_ULLONG)(a[1])*(a[1]);
		r[2]=Lw(t); r[3]=Hw(t);
		if (--n == 0) break;

		t=(BN_ULLONG)(a[2])*(a[2]);
		r[4]=Lw(t); r[5]=Hw(t);
		if (--n == 0) break;

		t=(BN_ULLONG)(a[3])*(a[3]);
		r[6]=Lw(t); r[7]=Hw(t);
		if (--n == 0) break;

		a+=4;
		r+=8;
		}
	}

BN_ULONG bn_add_words(r,a,b,n)
BN_ULONG *r,*a,*b;
int n;
        {
	BN_ULLONG ll;

	ll=0;
	for (;;)
		{
		ll+= (BN_ULLONG)a[0]+b[0];
		r[0]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		if (--n <= 0) break;

		ll+= (BN_ULLONG)a[1]+b[1];
		r[1]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		if (--n <= 0) break;

		ll+= (BN_ULLONG)a[2]+b[2];
		r[2]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		if (--n <= 0) break;

		ll+= (BN_ULLONG)a[3]+b[3];
		r[3]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		if (--n <= 0) break;

		a+=4;
		b+=4;
		r+=4;
		}
	return(ll&BN_MASK2);
	}

#else

BN_ULONG bn_mul_add_words(rp,ap,num,w)
BN_ULONG *rp,*ap;
int num;
BN_ULONG w;
	{
	BN_ULONG c=0;
	BN_ULONG bl,bh;

	bl=LBITS(w);
	bh=HBITS(w);

	for (;;)
		{
		mul_add(rp[0],ap[0],bl,bh,c);
		if (--num == 0) break;
		mul_add(rp[1],ap[1],bl,bh,c);
		if (--num == 0) break;
		mul_add(rp[2],ap[2],bl,bh,c);
		if (--num == 0) break;
		mul_add(rp[3],ap[3],bl,bh,c);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
		}
	return(c);
	} 

BN_ULONG bn_mul_words(rp,ap,num,w)
BN_ULONG *rp,*ap;
int num;
BN_ULONG w;
	{
	BN_ULONG carry=0;
	BN_ULONG bl,bh;

	bl=LBITS(w);
	bh=HBITS(w);

	for (;;)
		{
		mul(rp[0],ap[0],bl,bh,carry);
		if (--num == 0) break;
		mul(rp[1],ap[1],bl,bh,carry);
		if (--num == 0) break;
		mul(rp[2],ap[2],bl,bh,carry);
		if (--num == 0) break;
		mul(rp[3],ap[3],bl,bh,carry);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
		}
	return(carry);
	} 

void bn_sqr_words(r,a,n)
BN_ULONG *r,*a;
int n;
        {
	for (;;)
		{
		sqr64(r[0],r[1],a[0]);
		if (--n == 0) break;

		sqr64(r[2],r[3],a[1]);
		if (--n == 0) break;

		sqr64(r[4],r[5],a[2]);
		if (--n == 0) break;

		sqr64(r[6],r[7],a[3]);
		if (--n == 0) break;

		a+=4;
		r+=8;
		}
	}

BN_ULONG bn_add_words(r,a,b,n)
BN_ULONG *r,*a,*b;
int n;
        {
	BN_ULONG t1,t2;
	int carry,i;

	carry=0;
	for (i=0; i<n; i++)
		{
		t1= *(a++);
		t2= *(b++);
		if (carry)
			{
			carry=(t2 >= ((~t1)&BN_MASK2));
			t2=(t1+t2+1)&BN_MASK2;
			}
		else
			{
			t2=(t1+t2)&BN_MASK2;
			carry=(t2<t1);
			}
		*(r++)=t2;
		}
	return(carry);
	}

#endif

#if defined(BN_LLONG) && defined(BN_DIV2W)

BN_ULONG bn_div64(h,l,d)
BN_ULONG h,l,d;
	{
	return((BN_ULONG)(((((BN_ULLONG)h)<<BN_BITS2)|l)/(BN_ULLONG)d));
	}

#else

/* Divide h-l by d and return the result. */
/* I need to test this some more :-( */
BN_ULONG bn_div64(h,l,d)
BN_ULONG h,l,d;
	{
	BN_ULONG dh,dl,q,ret=0,th,tl,t;
	int i,count=2;

	if (d == 0) return(BN_MASK2);

	i=BN_num_bits_word(d);
	if ((i != BN_BITS2) && (h > (BN_ULONG)1<<i))
		{
#if !defined(NO_STDIO) && !defined(WIN16)
		fprintf(stderr,"Division would overflow (%d)\n",i);
#endif
		abort();
		}
	i=BN_BITS2-i;
	if (h >= d) h-=d;

	if (i)
		{
		d<<=i;
		h=(h<<i)|(l>>(BN_BITS2-i));
		l<<=i;
		}
	dh=(d&BN_MASK2h)>>BN_BITS4;
	dl=(d&BN_MASK2l);
	for (;;)
		{
		if ((h>>BN_BITS4) == dh)
			q=BN_MASK2l;
		else
			q=h/dh;

		for (;;)
			{
			t=(h-q*dh);
			if ((t&BN_MASK2h) ||
				((dl*q) <= (
					(t<<BN_BITS4)+
					((l&BN_MASK2h)>>BN_BITS4))))
				break;
			q--;
			}
		th=q*dh;
		tl=q*dl;
		t=(tl>>BN_BITS4);
		tl=(tl<<BN_BITS4)&BN_MASK2h;
		th+=t;

		if (l < tl) th++;
		l-=tl;
		if (h < th)
			{
			h+=d;
			q--;
			}
		h-=th;

		if (--count == 0) break;

		ret=q<<BN_BITS4;
		h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
		l=(l&BN_MASK2l)<<BN_BITS4;
		}
	ret|=q;
	return(ret);
	}
#endif

