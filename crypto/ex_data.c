/* crypto/ex_data.c */
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
#include "buffer.h"
#include "bio.h"
#include "lhash.h"
#include "cryptlib.h"

int CRYPTO_get_ex_new_index(idx,skp,argl,argp,new_func,dup_func,free_func)
int idx;
STACK **skp;
long argl;
char *argp;
int (*new_func)();
int (*dup_func)();
void (*free_func)();
	{
	CRYPTO_EX_DATA_FUNCS *a;

	if (*skp == NULL)
		*skp=sk_new_null();
	if (*skp == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX,ERR_R_MALLOC_FAILURE);
		return(-1);
		}
	a=(CRYPTO_EX_DATA_FUNCS *)Malloc(sizeof(CRYPTO_EX_DATA_FUNCS));
	if (a == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX,ERR_R_MALLOC_FAILURE);
		return(-1);
		}
	a->argl=argl;
	a->argp=argp;
	a->new_func=new_func;
	a->dup_func=dup_func;
	a->free_func=free_func;
	while (sk_num(*skp) <= idx)
		{
		if (!sk_push(*skp,NULL))
			{
			CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX,ERR_R_MALLOC_FAILURE);
			Free(a);
			return(-1);
			}
		}
	sk_value(*skp,idx)=(char *)a;
	return(idx);
	}

int CRYPTO_set_ex_data(ad,idx,val)
CRYPTO_EX_DATA *ad;
int idx;
char *val;
	{
	int i;

	if (ad->sk == NULL)
		{
		if ((ad->sk=sk_new_null()) == NULL)
			{
			CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA,ERR_R_MALLOC_FAILURE);
			return(0);
			}
		}
	i=sk_num(ad->sk);

	while (i <= idx)
		{
		if (!sk_push(ad->sk,NULL))
			{
			CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA,ERR_R_MALLOC_FAILURE);
			return(0);
			}
		i++;
		}
	sk_value(ad->sk,idx)=val;
	return(1);
	}

char *CRYPTO_get_ex_data(ad,idx)
CRYPTO_EX_DATA *ad;
int idx;
	{
	if (ad->sk == NULL)
		return(0);
	else if (idx >= sk_num(ad->sk))
		return(0);
	else
		return(sk_value(ad->sk,idx));
	}

/* The callback is called with the 'object', which is the origional data object
 * being duplicated, a pointer to the
 * 'new' object to be inserted, the index, and the argi/argp
 */
int CRYPTO_dup_ex_data(meth,to,from)
STACK *meth;
CRYPTO_EX_DATA *to,*from;
	{
	int i,j,m,r;
	CRYPTO_EX_DATA_FUNCS *mm;
	char *from_d;

	if (meth == NULL) return(1);
	if (from->sk == NULL) return(1);
	m=sk_num(meth);
	j=sk_num(from->sk);
	for (i=0; i<j; i++)
		{
		from_d=CRYPTO_get_ex_data(from,i);
		if (i < m)
			{
			mm=(CRYPTO_EX_DATA_FUNCS *)sk_value(meth,i);
			if (mm->dup_func != NULL)
				r=mm->dup_func(to,from,(char **)&from_d,i,
					mm->argl,mm->argp);
			}
		CRYPTO_set_ex_data(to,i,from_d);
		}
	return(1);
	}

/* Call each free callback */
void CRYPTO_free_ex_data(meth,obj,ad)
STACK *meth;
char *obj;
CRYPTO_EX_DATA *ad;
	{
	CRYPTO_EX_DATA_FUNCS *m;
	char *ptr;
	int i,max;

	if (meth != NULL)
		{
		max=sk_num(meth);
		for (i=0; i<max; i++)
			{
			m=(CRYPTO_EX_DATA_FUNCS *)sk_value(meth,i);
			if ((m != NULL) && (m->free_func != NULL))
				{
				ptr=CRYPTO_get_ex_data(ad,i);
				m->free_func(obj,ptr,ad,i,m->argl,m->argp);
				}
			}
		}
	if (ad->sk != NULL)
		{
		sk_free(ad->sk);
		ad->sk=NULL;
		}
	}

void CRYPTO_new_ex_data(meth,obj,ad)
STACK *meth;
char *obj;
CRYPTO_EX_DATA *ad;
	{
	CRYPTO_EX_DATA_FUNCS *m;
	char *ptr;
	int i,max;

	ad->sk=NULL;
	if (meth != NULL)
		{
		max=sk_num(meth);
		for (i=0; i<max; i++)
			{
			m=(CRYPTO_EX_DATA_FUNCS *)sk_value(meth,i);
			if ((m != NULL) && (m->new_func != NULL))
				{
				ptr=CRYPTO_get_ex_data(ad,i);
				m->new_func(obj,ptr,ad,i,m->argl,m->argp);
				}
			}
		}
	}


