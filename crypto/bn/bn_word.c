/* crypto/bn/bn_word.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

BN_ULONG BN_mod_word(a, w)
BIGNUM *a;
unsigned long w;
	{
#ifndef BN_LLONG
	BN_ULONG ret=0;
#else
	BN_ULLONG ret=0;
#endif
	int i;

	for (i=a->top-1; i>=0; i--)
		{
#ifndef BN_LLONG
		ret=((ret<<BN_BITS4)|((a->d[i]>>BN_BITS4)&BN_MASK2l))%(int)w;
		ret=((ret<<BN_BITS4)|(a->d[i]&BN_MASK2l))%(int)w;
#else
		ret=(BN_ULLONG)(((ret<<(BN_ULLONG)BN_BITS2)|a->d[i])%
			(BN_ULLONG)w);
#endif
		}
	return((BN_ULONG)ret);
	}

BN_ULONG BN_div_word(a, w)
BIGNUM *a;
unsigned long w;
	{
	BN_ULONG ret;
	int i;

	if (a->top == 0) return(0);
	ret=0;
	for (i=a->top-1; i>=0; i--)
		{
#ifndef BN_LLONG
		ret=((ret<<BN_BITS4)|((a->d[i]>>BN_BITS4)&BN_MASK2l))%(int)w;
		ret=((ret<<BN_BITS4)|(a->d[i]&BN_MASK2l))%(int)w;
#else
		BN_ULLONG ll;

		ll=((BN_ULLONG)ret<<(BN_ULONG)BN_BITS2)|a->d[i];
		a->d[i]=(BN_ULONG)(ll/w);
		ret=(BN_ULONG)(ll%w);
#endif
		}
	if (a->d[a->top-1] == 0)
		a->top--;
	return(ret);
	}

int BN_add_word(a, w)
BIGNUM *a;
unsigned long w;
	{
	BN_ULONG l;
	int i;

	if (bn_expand(a,a->top*BN_BITS2+1) == NULL) return(0);
	i=0;
	for (;;)
		{
		l=(a->d[i]+(BN_ULONG)w)&BN_MASK2;
		a->d[i]=l;
		if (w > l)
			w=1;
		else
			break;
		i++;
		}
	if (i >= a->top)
		a->top++;
	return(1);
	}

#ifdef undef
BN_ULONG *BN_mod_inverse_word(a)
BN_ULONG a;
	{
	BN_ULONG A,B,X,Y,M,D,R,RET,T;
	int sign,hight=1;

	X=0;
	Y=1;
	A=0;
	B=a;
	sign=1;

	while (B != 0)
		{

#endif

