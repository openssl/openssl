/* crypto/evp/names.c */
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
#include "evp.h"
#include "objects.h"

typedef struct aliases_st {
	char *alias;
	/* This must be the last field becaue I will allocate things
	 * so they go off the end of it */
	char name[4];
	} ALIASES;

static STACK /* ALIASES */ *aliases=NULL;
static STACK /* EVP_CIPHERS */ *ciphers=NULL;
static STACK /* EVP_MD */ *digests=NULL;

static int cipher_nid_cmp(a,b)
EVP_CIPHER **a,**b;
	{ return((*a)->nid - (*b)->nid); }

static int digest_type_cmp(a,b)
EVP_MD **a,**b;
	{ return((*a)->pkey_type - (*b)->pkey_type); }

int EVP_add_cipher(c)
EVP_CIPHER *c;
	{
	int i;

	if (ciphers == NULL)
		{
		ciphers=sk_new(cipher_nid_cmp);
		if (ciphers == NULL) return(0);
		}
	if ((i=sk_find(ciphers,(char *)c)) >= 0)
		{
		if (sk_value(ciphers,i) == (char *)c)
			return(1);
		sk_delete(ciphers,i);
		}
	return(sk_push(ciphers,(char *)c));
	}

int EVP_add_digest(md)
EVP_MD *md;
	{
	int i;
	char *n;

	if (digests == NULL)
		{
		digests=sk_new(digest_type_cmp);
		if (digests == NULL) return(0);
		}
	if ((i=sk_find(digests,(char *)md)) >= 0)
		{
		if (sk_value(digests,i) == (char *)md)
			return(1);
		sk_delete(digests,i);
		}
	if (md->type != md->pkey_type)
		{
		n=OBJ_nid2sn(md->pkey_type);
		EVP_add_alias(n,OBJ_nid2sn(md->type));
		EVP_add_alias(n,OBJ_nid2ln(md->type));
		}
	sk_push(digests,(char *)md);
	return(1);
	}

static int alias_cmp(a,b)
ALIASES **a,**b;
	{
	return(strcmp((*a)->alias,(*b)->alias));
	}

int EVP_add_alias(name,aname)
char *name;
char *aname;
	{
	int l1,l2,i;
	ALIASES *a;
	char *p;

	if ((name == NULL) || (aname == NULL)) return(0);
	l1=strlen(name)+1;
	l2=strlen(aname)+1;
	i=sizeof(ALIASES)+l1+l2;
	if ((a=(ALIASES *)Malloc(i)) == NULL)
		return(0);
	strcpy(a->name,name);
	p= &(a->name[l1]);
	strcpy(p,aname);
	a->alias=p;

	if (aliases == NULL)
		{
		aliases=sk_new(alias_cmp);
		if (aliases == NULL) goto err;
		}

	if ((i=sk_find(aliases,(char *)a)) >= 0)
		{
		Free(sk_delete(aliases,i));
		}
	if (!sk_push(aliases,(char *)a)) goto err;
	return(1);
err:
	return(0);
	}

int EVP_delete_alias(name)
char *name;
	{
	ALIASES a;
	int i;

	if (aliases != NULL)
		{
		a.alias=name;
		if ((i=sk_find(aliases,(char *)&a)) >= 0)
			{
			Free(sk_delete(aliases,i));
			return(1);
			}
		}
	return(0);
	}

EVP_CIPHER *EVP_get_cipherbyname(name)
char *name;
	{
	int nid,num=6,i;
	EVP_CIPHER c,*cp;
	ALIASES a,*ap;

	if (ciphers == NULL) return(NULL);
	for (;;)
		{
		if (num-- <= 0) return(NULL);
		if (aliases != NULL)
			{
			a.alias=name;
			i=sk_find(aliases,(char *)&a);
			if (i >= 0)
				{
				ap=(ALIASES *)sk_value(aliases,i);
				name=ap->name;
				continue;
				}
			}

		nid=OBJ_txt2nid(name);
		if (nid == NID_undef) return(NULL);
		c.nid=nid;
		i=sk_find(ciphers,(char *)&c);
		if (i >= 0)
			{
			cp=(EVP_CIPHER *)sk_value(ciphers,i);
			return(cp);
			}
		else
			return(NULL);
		}
	}

EVP_MD *EVP_get_digestbyname(name)
char *name;
	{
	int nid,num=6,i;
	EVP_MD c,*cp;
	ALIASES a,*ap;

	if (digests == NULL) return(NULL);

	for (;;)
		{
		if (num-- <= 0) return(NULL);

		if (aliases != NULL)
			{
			a.alias=name;
			i=sk_find(aliases,(char *)&a);
			if (i >= 0)
				{
				ap=(ALIASES *)sk_value(aliases,i);
				name=ap->name;
				continue;
				}
			}

		nid=OBJ_txt2nid(name);
		if (nid == NID_undef) return(NULL);
		c.pkey_type=nid;
		i=sk_find(digests,(char *)&c);
		if (i >= 0)
			{
			cp=(EVP_MD *)sk_value(digests,i);
			return(cp);
			}
		else
			return(NULL);
		}
	}

void EVP_cleanup()
	{
	int i;

	if (aliases != NULL)
		{
		for (i=0; i<sk_num(aliases); i++)
			Free(sk_value(aliases,i));
		sk_free(aliases);
		aliases=NULL;
		}
	if (ciphers != NULL)
		{
		sk_free(ciphers);
		ciphers=NULL;
		}
	if (digests != NULL)
		{
		sk_free(digests);
		digests=NULL;
		}
	}
