/* crypto/objects/obj_dat.c */
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
#include <ctype.h>
#include "cryptlib.h"
#include "lhash.h"
#include "asn1.h"
#include "objects.h"

/* obj_dat.h is generated from objects.h by obj_dat.pl */
#include "obj_dat.h"

#ifndef NOPROTO
static int sn_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
static int ln_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
static int obj_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
#else
static int sn_cmp();
static int ln_cmp();
static int obj_cmp();
#endif

#define ADDED_DATA	0
#define ADDED_SNAME	1
#define ADDED_LNAME	2
#define ADDED_NID	3

typedef struct added_obj_st
	{
	int type;
	ASN1_OBJECT *obj;
	} ADDED_OBJ;

static int new_nid=NUM_NID;
static LHASH *added=NULL;

static int sn_cmp(ap,bp)
ASN1_OBJECT **ap;
ASN1_OBJECT **bp;
	{ return(strcmp((*ap)->sn,(*bp)->sn)); }

static int ln_cmp(ap,bp)
ASN1_OBJECT **ap;
ASN1_OBJECT **bp;
	{ return(strcmp((*ap)->ln,(*bp)->ln)); }

static unsigned long add_hash(ca)
ADDED_OBJ *ca;
	{
	ASN1_OBJECT *a;
	int i;
	unsigned long ret=0;
	unsigned char *p;

	a=ca->obj;
	switch (ca->type)
		{
	case ADDED_DATA:
		ret=a->length<<20L;
		p=(unsigned char *)a->data;
		for (i=0; i<a->length; i++)
			ret^=p[i]<<((i*3)%24);
		break;
	case ADDED_SNAME:
		ret=lh_strhash(a->sn);
		break;
	case ADDED_LNAME:
		ret=lh_strhash(a->ln);
		break;
	case ADDED_NID:
		ret=a->nid;
		break;
	default:
		abort();
		}
	ret&=0x3fffffffL;
	ret|=ca->type<<30L;
	return(ret);
	}

static int add_cmp(ca,cb)
ADDED_OBJ *ca,*cb;
	{
	ASN1_OBJECT *a,*b;
	int i;

	i=ca->type-cb->type;
	if (i) return(i);
	a=ca->obj;
	b=cb->obj;
	switch (ca->type)
		{
	case ADDED_DATA:
		i=(a->length - b->length);
		if (i) return(i);
		return(memcmp(a->data,b->data,a->length));
	case ADDED_SNAME:
		if (a->sn == NULL) return(-1);
		else if (b->sn == NULL) return(1);
		else return(strcmp(a->sn,b->sn));
	case ADDED_LNAME:
		if (a->ln == NULL) return(-1);
		else if (b->ln == NULL) return(1);
		else return(strcmp(a->ln,b->ln));
	case ADDED_NID:
		return(a->nid-b->nid);
	default:
		abort();
		}
	}

static int init_added()
	{
	if (added != NULL) return(1);
	added=lh_new(add_hash,add_cmp);
	return(added != NULL);
	}

static void cleanup1(a)
ADDED_OBJ *a;
	{
	a->obj->nid=0;
	a->obj->flags|=ASN1_OBJECT_FLAG_DYNAMIC|
	                ASN1_OBJECT_FLAG_DYNAMIC_STRINGS;
	}

static void cleanup2(a)
ADDED_OBJ *a;
	{ a->obj->nid++; }

static void cleanup3(a)
ADDED_OBJ *a;
	{
	if (--a->obj->nid == 0)
		ASN1_OBJECT_free(a->obj);
	Free(a);
	}

void OBJ_cleanup()
	{
	if (added == NULL) return;
	added->down_load=0;
	lh_doall(added,cleanup1); /* zero counters */
	lh_doall(added,cleanup2); /* set counters */
	lh_doall(added,cleanup3); /* free objects */
	lh_free(added);
	added=NULL;
	}

int OBJ_new_nid(num)
int num;
	{
	int i;

	i=new_nid;
	new_nid+=num;
	return(i);
	}

int OBJ_add_object(obj)
ASN1_OBJECT *obj;
	{
	ASN1_OBJECT *o;
	ADDED_OBJ *ao[4],*aop;
	int i;

	if (added == NULL)
		if (!init_added()) return(0);
	if ((o=OBJ_dup(obj)) == NULL) goto err;
	ao[ADDED_DATA]=NULL;
	ao[ADDED_SNAME]=NULL;
	ao[ADDED_LNAME]=NULL;
	ao[ADDED_NID]=NULL;
	ao[ADDED_NID]=(ADDED_OBJ *)Malloc(sizeof(ADDED_OBJ));
	if ((o->length != 0) && (obj->data != NULL))
		ao[ADDED_DATA]=(ADDED_OBJ *)Malloc(sizeof(ADDED_OBJ));
	if (o->sn != NULL)
		ao[ADDED_SNAME]=(ADDED_OBJ *)Malloc(sizeof(ADDED_OBJ));
	if (o->ln != NULL)
		ao[ADDED_LNAME]=(ADDED_OBJ *)Malloc(sizeof(ADDED_OBJ));

	for (i=ADDED_DATA; i<=ADDED_NID; i++)
		{
		if (ao[i] != NULL)
			{
			ao[i]->type=i;
			ao[i]->obj=o;
			aop=(ADDED_OBJ *)lh_insert(added,(char *)ao[i]);
			/* memory leak, buit should not normally matter */
			if (aop != NULL)
				Free(aop);
			}
		}
	o->flags&= ~(ASN1_OBJECT_FLAG_DYNAMIC|ASN1_OBJECT_FLAG_DYNAMIC_STRINGS);
	return(o->nid);
err:
	for (i=ADDED_DATA; i<=ADDED_NID; i++)
		if (ao[i] != NULL) Free(ao[i]);
	if (o != NULL) Free(o);
	return(NID_undef);
	}

ASN1_OBJECT *OBJ_nid2obj(n)
int n;
	{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
		{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			OBJerr(OBJ_F_OBJ_NID2OBJ,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		return((ASN1_OBJECT *)&(nid_objs[n]));
		}
	else if (added == NULL)
		return(NULL);
	else
		{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL)
			return(adp->obj);
		else
			{
			OBJerr(OBJ_F_OBJ_NID2OBJ,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		}
	}

char *OBJ_nid2sn(n)
int n;
	{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
		{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			OBJerr(OBJ_F_OBJ_NID2SN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		return(nid_objs[n].sn);
		}
	else if (added == NULL)
		return(NULL);
	else
		{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL)
			return(adp->obj->sn);
		else
			{
			OBJerr(OBJ_F_OBJ_NID2SN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		}
	}

char *OBJ_nid2ln(n)
int n;
	{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
		{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			OBJerr(OBJ_F_OBJ_NID2LN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		return(nid_objs[n].ln);
		}
	else if (added == NULL)
		return(NULL);
	else
		{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL)
			return(adp->obj->ln);
		else
			{
			OBJerr(OBJ_F_OBJ_NID2LN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		}
	}

int OBJ_obj2nid(a)
ASN1_OBJECT *a;
	{
	ASN1_OBJECT **op;
	ADDED_OBJ ad,*adp;

	if (a == NULL)
		return(NID_undef);
	if (a->nid != 0)
		return(a->nid);

	if (added != NULL)
		{
		ad.type=ADDED_DATA;
		ad.obj=a;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=(ASN1_OBJECT **)OBJ_bsearch((char *)&a,(char *)obj_objs,NUM_OBJ,
		sizeof(ASN1_OBJECT *),(int (*)())obj_cmp);
	if (op == NULL)
		return(NID_undef);
	return((*op)->nid);
	}

int OBJ_txt2nid(s)
char *s;
	{
	int ret;

	ret=OBJ_sn2nid(s);
	if (ret == NID_undef)
		{
		ret=OBJ_ln2nid(s);
		if (ret == NID_undef)
			{
			ASN1_OBJECT *op=NULL;
			unsigned char *buf,*p;
			int i;

			i=a2d_ASN1_OBJECT(NULL,0,s,-1);
			if (i <= 0)
				{
				/* clear the error */
				ERR_get_error();
				return(0);
				}

			if ((buf=(unsigned char *)Malloc(i)) == NULL)
				return(NID_undef);
			a2d_ASN1_OBJECT(buf,i,s,-1);
			p=buf;
			op=d2i_ASN1_OBJECT(NULL,&p,i);
			if (op == NULL) return(NID_undef);
			ret=OBJ_obj2nid(op);
			ASN1_OBJECT_free(op);
			Free(buf);
			}
		}
	return(ret);
	}

int OBJ_ln2nid(s)
char *s;
	{
	ASN1_OBJECT o,*oo= &o,**op;
	ADDED_OBJ ad,*adp;

	o.ln=s;
	if (added != NULL)
		{
		ad.type=ADDED_LNAME;
		ad.obj= &o;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=(ASN1_OBJECT **)OBJ_bsearch((char *)&oo,(char *)ln_objs,NUM_LN,
		sizeof(ASN1_OBJECT *),(int (*)())ln_cmp);
	if (op == NULL) return(NID_undef);
	return((*op)->nid);
	}

int OBJ_sn2nid(s)
char *s;
	{
	ASN1_OBJECT o,*oo= &o,**op;
	ADDED_OBJ ad,*adp;

	o.sn=s;
	if (added != NULL)
		{
		ad.type=ADDED_SNAME;
		ad.obj= &o;
		adp=(ADDED_OBJ *)lh_retrieve(added,(char *)&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=(ASN1_OBJECT **)OBJ_bsearch((char *)&oo,(char *)sn_objs,NUM_SN,
		sizeof(ASN1_OBJECT *),(int (*)())sn_cmp);
	if (op == NULL) return(NID_undef);
	return((*op)->nid);
	}

static int obj_cmp(ap, bp)
ASN1_OBJECT **ap;
ASN1_OBJECT **bp;
	{
	int j;
	ASN1_OBJECT *a= *ap;
	ASN1_OBJECT *b= *bp;

	j=(a->length - b->length);
        if (j) return(j);
	return(memcmp(a->data,b->data,a->length));
        }

char *OBJ_bsearch(key,base,num,size,cmp)
char *key;
char *base;
int num;
int size;
int (*cmp)();
	{
	int l,h,i,c;
	char *p;

	if (num == 0) return(NULL);
	l=0;
	h=num;
	while (l < h)
		{
		i=(l+h)/2;
		p= &(base[i*size]);
		c=(*cmp)(key,p);
		if (c < 0)
			h=i;
		else if (c > 0)
			l=i+1;
		else
			return(p);
		}
	return(NULL);
	}

int OBJ_create_objects(in)
BIO *in;
	{
	MS_STATIC char buf[512];
	int i,num= -1;
	char *o,*s,*l=NULL;

	for (;;)
		{
		s=o=NULL;
		i=BIO_gets(in,buf,512);
		if (i <= 0) return(num);
		buf[i-1]='\0';
		if (!isalnum(buf[0])) return(num);
		o=s=buf;
		while (isdigit(*s) || (*s == '.'))
			s++;
		if (*s != '\0')
			{
			*(s++)='\0';
			while (isspace(*s))
				s++;
			if (*s == '\0')
				s=NULL;
			else
				{
				l=s;
				while ((*l != '\0') && !isspace(*l))
					l++;
				if (*l != '\0')
					{
					*(l++)='\0';
					while (isspace(*l))
						l++;
					if (*l == '\0') l=NULL;
					}
				else
					l=NULL;
				}
			}
		else
			s=NULL;
		if ((o == NULL) || (*o == '\0')) return(num);
		if (!OBJ_create(o,s,l)) return(num);
		num++;
		}
	return(num);
	}

int OBJ_create(oid,sn,ln)
char *oid;
char *sn;
char *ln;
	{
	int ok=0;
	ASN1_OBJECT *op=NULL;
	unsigned char *buf;
	int i;

	i=a2d_ASN1_OBJECT(NULL,0,oid,-1);
	if (i <= 0) return(0);

	if ((buf=(unsigned char *)Malloc(i)) == NULL)
		{
		OBJerr(OBJ_F_OBJ_CREATE,OBJ_R_MALLOC_FAILURE);
		return(0);
		}
	i=a2d_ASN1_OBJECT(buf,i,oid,-1);
	op=(ASN1_OBJECT *)ASN1_OBJECT_create(OBJ_new_nid(1),buf,i,sn,ln);
	if (op == NULL) 
		goto err;
	ok=OBJ_add_object(op);
err:
	ASN1_OBJECT_free(op);
	Free((char *)buf);
	return(ok);
	}

