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
#include <openssl/lhash.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>

/* obj_dat.h is generated from objects.h by obj_dat.pl */
#ifndef NO_OBJECT
#include "obj_dat.h"
#else
/* You will have to load all the objects needed manually in the application */
#define NUM_NID 0
#define NUM_SN 0
#define NUM_LN 0
#define NUM_OBJ 0
static unsigned char lvalues[1];
static ASN1_OBJECT nid_objs[1];
static ASN1_OBJECT *sn_objs[1];
static ASN1_OBJECT *ln_objs[1];
static ASN1_OBJECT *obj_objs[1];
#endif

static int sn_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
static int ln_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
static int obj_cmp(ASN1_OBJECT **a, ASN1_OBJECT **b);
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

static int sn_cmp(ASN1_OBJECT **ap, ASN1_OBJECT **bp)
	{ return(strcmp((*ap)->sn,(*bp)->sn)); }

static int ln_cmp(ASN1_OBJECT **ap, ASN1_OBJECT **bp)
	{ return(strcmp((*ap)->ln,(*bp)->ln)); }

static unsigned long add_hash(ADDED_OBJ *ca)
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

static int add_cmp(ADDED_OBJ *ca, ADDED_OBJ *cb)
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
	return(1); /* should not get here */
	}

static int init_added(void)
	{
	if (added != NULL) return(1);
	added=lh_new(add_hash,add_cmp);
	return(added != NULL);
	}

static void cleanup1(ADDED_OBJ *a)
	{
	a->obj->nid=0;
	a->obj->flags|=ASN1_OBJECT_FLAG_DYNAMIC|
	                ASN1_OBJECT_FLAG_DYNAMIC_STRINGS|
			ASN1_OBJECT_FLAG_DYNAMIC_DATA;
	}

static void cleanup2(ADDED_OBJ *a)
	{ a->obj->nid++; }

static void cleanup3(ADDED_OBJ *a)
	{
	if (--a->obj->nid == 0)
		ASN1_OBJECT_free(a->obj);
	Free(a);
	}

void OBJ_cleanup(void)
	{
	if (added == NULL) return;
	added->down_load=0;
	lh_doall(added,cleanup1); /* zero counters */
	lh_doall(added,cleanup2); /* set counters */
	lh_doall(added,cleanup3); /* free objects */
	lh_free(added);
	added=NULL;
	}

int OBJ_new_nid(int num)
	{
	int i;

	i=new_nid;
	new_nid+=num;
	return(i);
	}

int OBJ_add_object(ASN1_OBJECT *obj)
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
	o->flags&= ~(ASN1_OBJECT_FLAG_DYNAMIC|ASN1_OBJECT_FLAG_DYNAMIC_STRINGS|
			ASN1_OBJECT_FLAG_DYNAMIC_DATA);

	return(o->nid);
err:
	for (i=ADDED_DATA; i<=ADDED_NID; i++)
		if (ao[i] != NULL) Free(ao[i]);
	if (o != NULL) Free(o);
	return(NID_undef);
	}

ASN1_OBJECT *OBJ_nid2obj(int n)
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

const char *OBJ_nid2sn(int n)
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

const char *OBJ_nid2ln(int n)
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

int OBJ_obj2nid(ASN1_OBJECT *a)
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

/* Convert an object name into an ASN1_OBJECT
 * if "noname" is not set then search for short and long names first.
 * This will convert the "dotted" form into an object: unlike OBJ_txt2nid
 * it can be used with any objects, not just registered ones.
 */

ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name)
	{
	int nid = NID_undef;
	ASN1_OBJECT *op=NULL;
	unsigned char *buf,*p;
	int i, j;

	if(!no_name) {
		if( ((nid = OBJ_sn2nid(s)) != NID_undef) ||
			((nid = OBJ_ln2nid(s)) != NID_undef) ) 
					return OBJ_nid2obj(nid);
	}

	/* Work out size of content octets */
	i=a2d_ASN1_OBJECT(NULL,0,s,-1);
	if (i <= 0) {
		/* Clear the error */
		ERR_get_error();
		return NULL;
	}
	/* Work out total size */
	j = ASN1_object_size(0,i,V_ASN1_OBJECT);

	if((buf=(unsigned char *)Malloc(j)) == NULL) return NULL;

	p = buf;
	/* Write out tag+length */
	ASN1_put_object(&p,0,i,V_ASN1_OBJECT,V_ASN1_UNIVERSAL);
	/* Write out contents */
	a2d_ASN1_OBJECT(p,i,s,-1);
	
	p=buf;
	op=d2i_ASN1_OBJECT(NULL,&p,i);
	Free(buf);
	return op;
	}

int OBJ_obj2txt(char *buf, int buf_len, ASN1_OBJECT *a, int no_name)
{
	int i,idx=0,n=0,len,nid;
	unsigned long l;
	unsigned char *p;
	const char *s;
	char tbuf[32];

	if (buf_len <= 0) return(0);

	if ((a == NULL) || (a->data == NULL)) {
		buf[0]='\0';
		return(0);
	}

	nid=OBJ_obj2nid(a);
	if ((nid == NID_undef) || no_name) {
		len=a->length;
		p=a->data;

		idx=0;
		l=0;
		while (idx < a->length) {
			l|=(p[idx]&0x7f);
			if (!(p[idx] & 0x80)) break;
			l<<=7L;
			idx++;
		}
		idx++;
		i=(int)(l/40);
		if (i > 2) i=2;
		l-=(long)(i*40);

		sprintf(tbuf,"%d.%lu",i,l);
		i=strlen(tbuf);
		strncpy(buf,tbuf,buf_len);
		buf_len-=i;
		buf+=i;
		n+=i;

		l=0;
		for (; idx<len; idx++) {
			l|=p[idx]&0x7f;
			if (!(p[idx] & 0x80)) {
				sprintf(tbuf,".%lu",l);
				i=strlen(tbuf);
				if (buf_len > 0)
					strncpy(buf,tbuf,buf_len);
				buf_len-=i;
				buf+=i;
				n+=i;
				l=0;
			}
			l<<=7L;
		}
	} else {
		s=OBJ_nid2ln(nid);
		if (s == NULL)
			s=OBJ_nid2sn(nid);
		strncpy(buf,s,buf_len);
		n=strlen(s);
	}
	buf[buf_len-1]='\0';
	return(n);
}

int OBJ_txt2nid(char *s)
{
	ASN1_OBJECT *obj;
	int nid;
	obj = OBJ_txt2obj(s, 0);
	nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);
	return nid;
}

int OBJ_ln2nid(const char *s)
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

int OBJ_sn2nid(const char *s)
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

static int obj_cmp(ASN1_OBJECT **ap, ASN1_OBJECT **bp)
	{
	int j;
	ASN1_OBJECT *a= *ap;
	ASN1_OBJECT *b= *bp;

	j=(a->length - b->length);
        if (j) return(j);
	return(memcmp(a->data,b->data,a->length));
        }

char *OBJ_bsearch(char *key, char *base, int num, int size, int (*cmp)())
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
#ifdef CHARSET_EBCDIC
/* THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and
 * I don't have perl (yet), we revert to a *LINEAR* search
 * when the object wasn't found in the binary search.
 */
	for (i=0; i<num; ++i) {
		p= &(base[i*size]);
		if ((*cmp)(key,p) == 0)
			return p;
	}
#endif
	return(NULL);
	}

int OBJ_create_objects(BIO *in)
	{
	MS_STATIC char buf[512];
	int i,num=0;
	char *o,*s,*l=NULL;

	for (;;)
		{
		s=o=NULL;
		i=BIO_gets(in,buf,512);
		if (i <= 0) return(num);
		buf[i-1]='\0';
		if (!isalnum((unsigned char)buf[0])) return(num);
		o=s=buf;
		while (isdigit((unsigned char)*s) || (*s == '.'))
			s++;
		if (*s != '\0')
			{
			*(s++)='\0';
			while (isspace((unsigned char)*s))
				s++;
			if (*s == '\0')
				s=NULL;
			else
				{
				l=s;
				while ((*l != '\0') && !isspace((unsigned char)*l))
					l++;
				if (*l != '\0')
					{
					*(l++)='\0';
					while (isspace((unsigned char)*l))
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
	/* return(num); */
	}

int OBJ_create(char *oid, char *sn, char *ln)
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

