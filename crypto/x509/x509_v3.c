/* crypto/x509/x509_v3.c */
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
#include "stack.h"
#include "cryptlib.h"
#include "asn1.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"

#ifndef NOPROTO
static X509_EXTENSION_METHOD *find_by_nid(int nid);
static int xem_cmp(X509_EXTENSION_METHOD **a, X509_EXTENSION_METHOD **b);
#else
static X509_EXTENSION_METHOD *find_by_nid();
static int xem_cmp();
#endif

static STACK *extensions=NULL;

int X509v3_get_ext_count(x)
STACK *x;
	{
	if (x == NULL) return(0);
	return(sk_num(x));
	}

int X509v3_get_ext_by_NID(x,nid,lastpos)
STACK *x;
int nid;
int lastpos;
	{
	ASN1_OBJECT *obj;

	obj=OBJ_nid2obj(nid);
	if (obj == NULL) return(-2);
	return(X509v3_get_ext_by_OBJ(x,obj,lastpos));
	}

int X509v3_get_ext_by_OBJ(sk,obj,lastpos)
STACK *sk;
ASN1_OBJECT *obj;
int lastpos;
	{
	int n;
	X509_EXTENSION *ex;

	if (sk == NULL) return(-1);
	lastpos++;
	if (lastpos < 0)
		lastpos=0;
	n=sk_num(sk);
	for ( ; lastpos < n; lastpos++)
		{
		ex=(X509_EXTENSION *)sk_value(sk,lastpos);
		if (OBJ_cmp(ex->object,obj) == 0)
			return(lastpos);
		}
	return(-1);
	}

int X509v3_get_ext_by_critical(sk,crit,lastpos)
STACK *sk;
int crit;
int lastpos;
	{
	int n;
	X509_EXTENSION *ex;

	if (sk == NULL) return(-1);
	lastpos++;
	if (lastpos < 0)
		lastpos=0;
	n=sk_num(sk);
	for ( ; lastpos < n; lastpos++)
		{
		ex=(X509_EXTENSION *)sk_value(sk,lastpos);
		if (	(ex->critical && crit) ||
			(!ex->critical && !crit))
			return(lastpos);
		}
	return(-1);
	}

X509_EXTENSION *X509v3_get_ext(x,loc)
STACK *x;
int loc;
	{
	if ((x == NULL) || (sk_num(x) <= loc) || (loc < 0))
		return(NULL);
	else
		return((X509_EXTENSION *)sk_value(x,loc));
	}

X509_EXTENSION *X509v3_delete_ext(x,loc)
STACK *x;
int loc;
	{
	X509_EXTENSION *ret;

	if ((x == NULL) || (sk_num(x) <= loc) || (loc < 0))
		return(NULL);
	ret=(X509_EXTENSION *)sk_delete(x,loc);
	return(ret);
	}

STACK *X509v3_add_ext(x,ex,loc)
STACK **x;
X509_EXTENSION *ex;
int loc;
	{
	X509_EXTENSION *new_ex=NULL;
	int n;
	STACK *sk=NULL;

	if ((x != NULL) && (*x == NULL))
		{
		if ((sk=sk_new_null()) == NULL)
			goto err;
		}
	else
		sk= *x;

	n=sk_num(sk);
	if (loc > n) loc=n;
	else if (loc < 0) loc=n;

	if ((new_ex=X509_EXTENSION_dup(ex)) == NULL)
		goto err2;
	if (!sk_insert(sk,(char *)new_ex,loc))
		goto err;
	if ((x != NULL) && (*x == NULL))
		*x=sk;
	return(sk);
err:
	X509err(X509_F_X509V3_ADD_EXT,ERR_R_MALLOC_FAILURE);
err2:
	if (new_ex != NULL) X509_EXTENSION_free(new_ex);
	if (sk != NULL) sk_free(sk);
	return(NULL);
	}

X509_EXTENSION *X509_EXTENSION_create_by_NID(ex,nid,crit,data)
X509_EXTENSION **ex;
int nid;
int crit;
ASN1_OCTET_STRING *data;
	{
	ASN1_OBJECT *obj;
	X509_EXTENSION *ret;

	obj=OBJ_nid2obj(nid);
	if (obj == NULL)
		{
		X509err(X509_F_X509_EXTENSION_CREATE_BY_NID,X509_R_UNKNOWN_NID);
		return(NULL);
		}
	ret=X509_EXTENSION_create_by_OBJ(ex,obj,crit,data);
	if (ret == NULL) ASN1_OBJECT_free(obj);
	return(ret);
	}

X509_EXTENSION *X509_EXTENSION_create_by_OBJ(ex,obj,crit,data)
X509_EXTENSION **ex;
ASN1_OBJECT *obj;
int crit;
ASN1_OCTET_STRING *data;
	{
	X509_EXTENSION *ret;

	if ((ex == NULL) || (*ex == NULL))
		{
		if ((ret=X509_EXTENSION_new()) == NULL)
			{
			X509err(X509_F_X509_EXTENSION_CREATE_BY_OBJ,ERR_R_MALLOC_FAILURE);
			return(NULL);
			}
		}
	else
		ret= *ex;

	if (!X509_EXTENSION_set_object(ret,obj))
		goto err;
	if (!X509_EXTENSION_set_critical(ret,crit))
		goto err;
	if (!X509_EXTENSION_set_data(ret,data))
		goto err;
	
	if ((ex != NULL) && (*ex == NULL)) *ex=ret;
	return(ret);
err:
	if ((ex == NULL) || (ret != *ex))
		X509_EXTENSION_free(ret);
	return(NULL);
	}

int X509_EXTENSION_set_object(ex,obj)
X509_EXTENSION *ex;
ASN1_OBJECT *obj;
	{
	if ((ex == NULL) || (obj == NULL))
		return(0);
	ASN1_OBJECT_free(ex->object);
	ex->object=OBJ_dup(obj);
	return(1);
	}

int X509_EXTENSION_set_critical(ex,crit)
X509_EXTENSION *ex;
int crit;
	{
	if (ex == NULL) return(0);
	ex->critical=(crit)?0xFF:0;
	return(1);
	}

int X509_EXTENSION_set_data(ex,data)
X509_EXTENSION *ex;
ASN1_OCTET_STRING *data;
	{
	int i;

	if (ex == NULL) return(0);
	i=ASN1_OCTET_STRING_set(ex->value,data->data,data->length);
	if (!i) return(0);
	return(1);
	}

ASN1_OBJECT *X509_EXTENSION_get_object(ex)
X509_EXTENSION *ex;
	{
	if (ex == NULL) return(NULL);
	return(ex->object);
	}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(ex)
X509_EXTENSION *ex;
	{
	if (ex == NULL) return(NULL);
	return(ex->value);
	}

int X509_EXTENSION_get_critical(ex)
X509_EXTENSION *ex;
	{
	if (ex == NULL) return(0);
	return(ex->critical);
	}

int X509v3_data_type_by_OBJ(obj)
ASN1_OBJECT *obj;
	{
	int nid;

	nid=OBJ_obj2nid(obj);
	if (nid == V_ASN1_UNDEF) return(V_ASN1_UNDEF);
	return(X509v3_data_type_by_NID(nid));
	}

int X509v3_data_type_by_NID(nid)
int nid;
	{
	X509_EXTENSION_METHOD *x;

	x=find_by_nid(nid);
	if (x == NULL)
		return(V_ASN1_UNDEF);
	else
		return(x->data_type);
	}

int X509v3_pack_type_by_OBJ(obj)
ASN1_OBJECT *obj;
	{
	int nid;

	nid=OBJ_obj2nid(obj);
	if (nid == NID_undef) return(X509_EXT_PACK_UNKNOWN);
	return(X509v3_pack_type_by_NID(nid));
	}

int X509v3_pack_type_by_NID(nid)
int nid;
	{
	X509_EXTENSION_METHOD *x;

	x=find_by_nid(nid);
	if (x == NULL)
		return(X509_EXT_PACK_UNKNOWN);
	else
		return(x->pack_type);
	}

static X509_EXTENSION_METHOD *find_by_nid(nid)
int nid;
	{
	X509_EXTENSION_METHOD x;
	int i;

	x.nid=nid;
	if (extensions == NULL) return(NULL);
	i=sk_find(extensions,(char *)&x);
	if (i < 0)
		return(NULL);
	else
		return((X509_EXTENSION_METHOD *)sk_value(extensions,i));
	}

static int xem_cmp(a,b)
X509_EXTENSION_METHOD **a,**b;
	{
	return((*a)->nid-(*b)->nid);
	}

void X509v3_cleanup_extensions()
	{
	int i;

	if (extensions != NULL)
		{
		for (i=0; i<sk_num(extensions); i++)
			Free(sk_value(extensions,i));
		sk_free(extensions);
		extensions=NULL;
		}
	}

int X509v3_add_extension(x)
X509_EXTENSION_METHOD *x;
	{
	X509_EXTENSION_METHOD *newx;

	if (extensions == NULL)
		{
		extensions=sk_new(xem_cmp);
		if (extensions == NULL) goto err;
		}
	newx=(X509_EXTENSION_METHOD *)Malloc(sizeof(X509_EXTENSION_METHOD));
	if (newx == NULL) goto err;
	newx->nid=x->nid;
	newx->data_type=x->data_type;
	newx->pack_type=x->pack_type;
	if (!sk_push(extensions,(char *)newx))
		{
		Free(newx);
		goto err;
		}
	return(1);
err:
	X509err(X509_F_X509V3_ADD_EXTENSION,ERR_R_MALLOC_FAILURE);
	return(0);
	}

