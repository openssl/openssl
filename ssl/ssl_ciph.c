/* ssl/ssl_ciph.c */
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
#include <openssl/objects.h>
#include <openssl/comp.h>
#include "ssl_locl.h"

#define SSL_ENC_DES_IDX		0
#define SSL_ENC_3DES_IDX	1
#define SSL_ENC_RC4_IDX		2
#define SSL_ENC_RC2_IDX		3
#define SSL_ENC_IDEA_IDX	4
#define SSL_ENC_eFZA_IDX	5
#define SSL_ENC_NULL_IDX	6
#define SSL_ENC_NUM_IDX		7

static const EVP_CIPHER *ssl_cipher_methods[SSL_ENC_NUM_IDX]={
	NULL,NULL,NULL,NULL,NULL,NULL,
	};

static STACK_OF(SSL_COMP) *ssl_comp_methods=NULL;

#define SSL_MD_MD5_IDX	0
#define SSL_MD_SHA1_IDX	1
#define SSL_MD_NUM_IDX	2
static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX]={
	NULL,NULL,
	};

typedef struct cipher_sort_st
	{
	SSL_CIPHER *cipher;
	int pref;
	} CIPHER_SORT;

#define CIPHER_ADD	1
#define CIPHER_KILL	2
#define CIPHER_DEL	3
#define CIPHER_ORD	4

typedef struct cipher_choice_st
	{
	int type;
	unsigned long algorithms;
	unsigned long mask;
	long top;
	} CIPHER_CHOICE;

typedef struct cipher_order_st
	{
	SSL_CIPHER *cipher;
	int active;
	int dead;
	struct cipher_order_st *next,*prev;
	} CIPHER_ORDER;

static SSL_CIPHER cipher_aliases[]={
	/* Don't include eNULL unless specifically enabled */
	{0,SSL_TXT_ALL, 0,SSL_ALL & ~SSL_eNULL, 0,SSL_ALL}, /* must be first */
	{0,SSL_TXT_kRSA,0,SSL_kRSA,  0,SSL_MKEY_MASK},
	{0,SSL_TXT_kDHr,0,SSL_kDHr,  0,SSL_MKEY_MASK},
	{0,SSL_TXT_kDHd,0,SSL_kDHd,  0,SSL_MKEY_MASK},
	{0,SSL_TXT_kEDH,0,SSL_kEDH,  0,SSL_MKEY_MASK},
	{0,SSL_TXT_kFZA,0,SSL_kFZA,  0,SSL_MKEY_MASK},
	{0,SSL_TXT_DH,	0,SSL_DH,    0,SSL_MKEY_MASK},
	{0,SSL_TXT_EDH,	0,SSL_EDH,   0,SSL_MKEY_MASK|SSL_AUTH_MASK},

	{0,SSL_TXT_aRSA,0,SSL_aRSA,  0,SSL_AUTH_MASK},
	{0,SSL_TXT_aDSS,0,SSL_aDSS,  0,SSL_AUTH_MASK},
	{0,SSL_TXT_aFZA,0,SSL_aFZA,  0,SSL_AUTH_MASK},
	{0,SSL_TXT_aNULL,0,SSL_aNULL,0,SSL_AUTH_MASK},
	{0,SSL_TXT_aDH, 0,SSL_aDH,   0,SSL_AUTH_MASK},
	{0,SSL_TXT_DSS,	0,SSL_DSS,   0,SSL_AUTH_MASK},

	{0,SSL_TXT_DES,	0,SSL_DES,   0,SSL_ENC_MASK},
	{0,SSL_TXT_3DES,0,SSL_3DES,  0,SSL_ENC_MASK},
	{0,SSL_TXT_RC4,	0,SSL_RC4,   0,SSL_ENC_MASK},
	{0,SSL_TXT_RC2,	0,SSL_RC2,   0,SSL_ENC_MASK},
	{0,SSL_TXT_IDEA,0,SSL_IDEA,  0,SSL_ENC_MASK},
	{0,SSL_TXT_eNULL,0,SSL_eNULL,0,SSL_ENC_MASK},
	{0,SSL_TXT_eFZA,0,SSL_eFZA,  0,SSL_ENC_MASK},

	{0,SSL_TXT_MD5,	0,SSL_MD5,   0,SSL_MAC_MASK},
	{0,SSL_TXT_SHA1,0,SSL_SHA1,  0,SSL_MAC_MASK},
	{0,SSL_TXT_SHA,	0,SSL_SHA,   0,SSL_MAC_MASK},

	{0,SSL_TXT_NULL,0,SSL_NULL,  0,SSL_ENC_MASK},
	{0,SSL_TXT_RSA,	0,SSL_RSA,   0,SSL_AUTH_MASK|SSL_MKEY_MASK},
	{0,SSL_TXT_ADH,	0,SSL_ADH,   0,SSL_AUTH_MASK|SSL_MKEY_MASK},
	{0,SSL_TXT_FZA,	0,SSL_FZA,   0,SSL_AUTH_MASK|SSL_MKEY_MASK|SSL_ENC_MASK},

	{0,SSL_TXT_EXP40, 0,SSL_EXP40, 0,SSL_EXP_MASK},
	{0,SSL_TXT_EXPORT,0,SSL_EXP40, 0,SSL_EXP_MASK},
	{0,SSL_TXT_EXP56, 0,SSL_EXP56, 0,SSL_EXP_MASK},
	{0,SSL_TXT_SSLV2, 0,SSL_SSLV2, 0,SSL_SSL_MASK},
	{0,SSL_TXT_SSLV3, 0,SSL_SSLV3, 0,SSL_SSL_MASK},
	{0,SSL_TXT_TLSV1, 0,SSL_TLSV1, 0,SSL_SSL_MASK},
	{0,SSL_TXT_LOW,   0,SSL_LOW,   0,SSL_STRONG_MASK},
	{0,SSL_TXT_MEDIUM,0,SSL_MEDIUM,0,SSL_STRONG_MASK},
	{0,SSL_TXT_HIGH,  0,SSL_HIGH,  0,SSL_STRONG_MASK},
	};

static int init_ciphers=1;
static void load_ciphers();

static int cmp_by_name(SSL_CIPHER **a, SSL_CIPHER **b)
	{
	return(strcmp((*a)->name,(*b)->name));
	}

static void load_ciphers(void)
	{
	init_ciphers=0;
	ssl_cipher_methods[SSL_ENC_DES_IDX]= 
		EVP_get_cipherbyname(SN_des_cbc);
	ssl_cipher_methods[SSL_ENC_3DES_IDX]=
		EVP_get_cipherbyname(SN_des_ede3_cbc);
	ssl_cipher_methods[SSL_ENC_RC4_IDX]=
		EVP_get_cipherbyname(SN_rc4);
	ssl_cipher_methods[SSL_ENC_RC2_IDX]= 
		EVP_get_cipherbyname(SN_rc2_cbc);
	ssl_cipher_methods[SSL_ENC_IDEA_IDX]= 
		EVP_get_cipherbyname(SN_idea_cbc);

	ssl_digest_methods[SSL_MD_MD5_IDX]=
		EVP_get_digestbyname(SN_md5);
	ssl_digest_methods[SSL_MD_SHA1_IDX]=
		EVP_get_digestbyname(SN_sha1);
	}

int ssl_cipher_get_evp(SSL_SESSION *s, const EVP_CIPHER **enc,
	     const EVP_MD **md, SSL_COMP **comp)
	{
	int i;
	SSL_CIPHER *c;

	c=s->cipher;
	if (c == NULL) return(0);
	if (comp != NULL)
		{
		SSL_COMP ctmp;

		if (s->compress_meth == 0)
			*comp=NULL;
		else if (ssl_comp_methods == NULL)
			{
			/* bad */
			*comp=NULL;
			}
		else
			{

			ctmp.id=s->compress_meth;
			i=sk_SSL_COMP_find(ssl_comp_methods,&ctmp);
			if (i >= 0)
				*comp=sk_SSL_COMP_value(ssl_comp_methods,i);
			else
				*comp=NULL;
			}
		}

	if ((enc == NULL) || (md == NULL)) return(0);

	switch (c->algorithms & SSL_ENC_MASK)
		{
	case SSL_DES:
		i=SSL_ENC_DES_IDX;
		break;
	case SSL_3DES:
		i=SSL_ENC_3DES_IDX;
		break;
	case SSL_RC4:
		i=SSL_ENC_RC4_IDX;
		break;
	case SSL_RC2:
		i=SSL_ENC_RC2_IDX;
		break;
	case SSL_IDEA:
		i=SSL_ENC_IDEA_IDX;
		break;
	case SSL_eNULL:
		i=SSL_ENC_NULL_IDX;
		break;
	default:
		i= -1;
		break;
		}

	if ((i < 0) || (i > SSL_ENC_NUM_IDX))
		*enc=NULL;
	else
		{
		if (i == SSL_ENC_NULL_IDX)
			*enc=EVP_enc_null();
		else
			*enc=ssl_cipher_methods[i];
		}

	switch (c->algorithms & SSL_MAC_MASK)
		{
	case SSL_MD5:
		i=SSL_MD_MD5_IDX;
		break;
	case SSL_SHA1:
		i=SSL_MD_SHA1_IDX;
		break;
	default:
		i= -1;
		break;
		}
	if ((i < 0) || (i > SSL_MD_NUM_IDX))
		*md=NULL;
	else
		*md=ssl_digest_methods[i];

	if ((*enc != NULL) && (*md != NULL))
		return(1);
	else
		return(0);
	}

#define ITEM_SEP(a) \
	(((a) == ':') || ((a) == ' ') || ((a) == ';') || ((a) == ','))

static void ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
	     CIPHER_ORDER **tail)
	{
	if (curr == *tail) return;
	if (curr == *head)
		*head=curr->next;
	if (curr->prev != NULL)
		curr->prev->next=curr->next;
	if (curr->next != NULL) /* should always be true */
		curr->next->prev=curr->prev;
	(*tail)->next=curr;
	curr->prev= *tail;
	curr->next=NULL;
	*tail=curr;
	}

STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(SSL_METHOD *ssl_method,
		STACK_OF(SSL_CIPHER) **cipher_list,
		STACK_OF(SSL_CIPHER) **cipher_list_by_id,
		char *str)
	{
	SSL_CIPHER *c;
	char *l;
	STACK_OF(SSL_CIPHER) *ret=NULL,*ok=NULL;
#define CL_BUF	40
	char buf[CL_BUF];
	char *tmp_str=NULL;
	unsigned long mask,algorithms,ma;
	char *start;
	int i,j,k,num=0,ch,multi;
	unsigned long al;
	STACK *ca_list=NULL;
	int current_x,num_x;
	CIPHER_CHOICE *ops=NULL;
	CIPHER_ORDER *list=NULL,*head=NULL,*tail=NULL,*curr,*tail2,*curr2;
	int list_num;
	int type;
	SSL_CIPHER c_tmp,*cp;

	if (str == NULL) return(NULL);

	if (strncmp(str,"DEFAULT",7) == 0)
		{
		i=strlen(str)+2+strlen(SSL_DEFAULT_CIPHER_LIST);
		if ((tmp_str=Malloc(i)) == NULL)
			{
			SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		strcpy(tmp_str,SSL_DEFAULT_CIPHER_LIST);
		strcat(tmp_str,":");
		strcat(tmp_str,&(str[7]));
		str=tmp_str;
		}
	if (init_ciphers) load_ciphers();

	num=ssl_method->num_ciphers();

	if ((ret=sk_SSL_CIPHER_new(NULL)) == NULL) goto err;
	if ((ca_list=(STACK *)sk_new(cmp_by_name)) == NULL) goto err;

	mask =SSL_kFZA;
#ifdef NO_RSA
	mask|=SSL_aRSA|SSL_kRSA;
#endif
#ifdef NO_DSA
	mask|=SSL_aDSS;
#endif
#ifdef NO_DH
	mask|=SSL_kDHr|SSL_kDHd|SSL_kEDH|SSL_aDH;
#endif

#ifdef SSL_FORBID_ENULL
	mask|=SSL_eNULL;
#endif

	mask|=(ssl_cipher_methods[SSL_ENC_DES_IDX ] == NULL)?SSL_DES :0;
	mask|=(ssl_cipher_methods[SSL_ENC_3DES_IDX] == NULL)?SSL_3DES:0;
	mask|=(ssl_cipher_methods[SSL_ENC_RC4_IDX ] == NULL)?SSL_RC4 :0;
	mask|=(ssl_cipher_methods[SSL_ENC_RC2_IDX ] == NULL)?SSL_RC2 :0;
	mask|=(ssl_cipher_methods[SSL_ENC_IDEA_IDX] == NULL)?SSL_IDEA:0;
	mask|=(ssl_cipher_methods[SSL_ENC_eFZA_IDX] == NULL)?SSL_eFZA:0;

	mask|=(ssl_digest_methods[SSL_MD_MD5_IDX ] == NULL)?SSL_MD5 :0;
	mask|=(ssl_digest_methods[SSL_MD_SHA1_IDX] == NULL)?SSL_SHA1:0;

	if ((list=(CIPHER_ORDER *)Malloc(sizeof(CIPHER_ORDER)*num)) == NULL)
		goto err;

	/* Get the initial list of ciphers */
	list_num=0;
	for (i=0; i<num; i++)
		{
		c=ssl_method->get_cipher((unsigned int)i);
		/* drop those that use any of that is not available */
		if ((c != NULL) && c->valid && !(c->algorithms & mask))
			{
			list[list_num].cipher=c;
			list[list_num].next=NULL;
			list[list_num].prev=NULL;
			list[list_num].active=0;
			list_num++;
			if (!sk_push(ca_list,(char *)c)) goto err;
			}
		}
	
	for (i=1; i<list_num-1; i++)
		{
		list[i].prev= &(list[i-1]);
		list[i].next= &(list[i+1]);
		}
	if (list_num > 0)
		{
		head= &(list[0]);
		head->prev=NULL;
		head->next= &(list[1]);
		tail= &(list[list_num-1]);
		tail->prev= &(list[list_num-2]);
		tail->next=NULL;
		}

	/* special case */
	cipher_aliases[0].algorithms &= ~mask;

	/* get the aliases */
	k=sizeof(cipher_aliases)/sizeof(SSL_CIPHER);
	for (j=0; j<k; j++)
		{
		al=cipher_aliases[j].algorithms;
		/* Drop those that are not relevent */
		if ((al & mask) == al) continue;
		if (!sk_push(ca_list,(char *)&(cipher_aliases[j]))) goto err;
		}

	/* ca_list now holds a 'stack' of SSL_CIPHERS, some real, some
	 * 'aliases' */

	/* how many parameters are there? */
	num=1;
	for (l=str; *l; l++)
		if (ITEM_SEP(*l))
			num++;
	ops=(CIPHER_CHOICE *)Malloc(sizeof(CIPHER_CHOICE)*num);
	if (ops == NULL) goto err;
	memset(ops,0,sizeof(CIPHER_CHOICE)*num);

	/* we now parse the input string and create our operations */
	l=str;
	i=0;
	current_x=0;

	for (;;)
		{
		ch= *l;

		if (ch == '\0') break;

		if (ch == '-')
			{ j=CIPHER_DEL; l++; }
		else if (ch == '+')
			{ j=CIPHER_ORD; l++; }
		else if (ch == '!')
			{ j=CIPHER_KILL; l++; }
		else	
			{ j=CIPHER_ADD; }

		if (ITEM_SEP(ch))
			{
			l++;
			continue;
			}
		ops[current_x].type=j;
		ops[current_x].algorithms=0;
		ops[current_x].mask=0;

		start=l;
		for (;;)
			{
			ch= *l;
			i=0;
#ifndef CHARSET_EBCDIC
			while (	((ch >= 'A') && (ch <= 'Z')) ||
				((ch >= '0') && (ch <= '9')) ||
				((ch >= 'a') && (ch <= 'z')) ||
				 (ch == '-'))
#else
			while (	isalnum(ch) || (ch == '-'))
#endif
				 {
				 buf[i]=ch;
				 ch= *(++l);
				 i++;
				 if (i >= (CL_BUF-2)) break;
				 }
			buf[i]='\0';

			/* check for multi-part specification */
			if (ch == '+')
				{
				multi=1;
				l++;
				}
			else
				multi=0;

			c_tmp.name=buf;
			j=sk_find(ca_list,(char *)&c_tmp);
			if (j < 0)
				goto end_loop;

			cp=(SSL_CIPHER *)sk_value(ca_list,j);
			ops[current_x].algorithms|=cp->algorithms;
			/* We add the SSL_SSL_MASK so we can match the
			 * SSLv2 and SSLv3 versions of RC4-MD5 */
			ops[current_x].mask|=cp->mask;
			if (!multi) break;
			}
		current_x++;
		if (ch == '\0') break;
end_loop:
		/* Make sure we scan until the next valid start point */
		while ((*l != '\0') && ITEM_SEP(*l))
			l++;
		}

	num_x=current_x;
	current_x=0;

	/* We will now process the list of ciphers, once for each category, to
	 * decide what we should do with it. */
	for (j=0; j<num_x; j++)
		{
		algorithms=ops[j].algorithms;
		type=ops[j].type;
		mask=ops[j].mask;

		curr=head;
		curr2=head;
		tail2=tail;
		for (;;)
			{
			if ((curr == NULL) || (curr == tail2)) break;
			curr=curr2;
			curr2=curr->next;

			cp=curr->cipher;
			ma=mask & cp->algorithms;
			if ((ma == 0) || ((ma & algorithms) != ma))
				{
				/* does not apply */
				continue;
				}

			/* add the cipher if it has not been added yet. */
			if (type == CIPHER_ADD)
				{
				if (!curr->active)
					{
					ll_append_tail(&head,curr,&tail);
					curr->active=1;
					}
				}
			/* Move the added cipher to this location */
			else if (type == CIPHER_ORD)
				{
				if (curr->active)
					{
					ll_append_tail(&head,curr,&tail);
					}
				}
			else if	(type == CIPHER_DEL)
				curr->active=0;
			if (type == CIPHER_KILL)
				{
				if (head == curr)
					head=curr->next;
				else
					curr->prev->next=curr->next;
				if (tail == curr)
					tail=curr->prev;
				curr->active=0;
				if (curr->next != NULL)
					curr->next->prev=curr->prev;
				if (curr->prev != NULL)
					curr->prev->next=curr->next;
				curr->next=NULL;
				curr->prev=NULL;
				}
			}
		}

	for (curr=head; curr != NULL; curr=curr->next)
		{
		if (curr->active)
			{
			sk_SSL_CIPHER_push(ret,curr->cipher);
#ifdef CIPHER_DEBUG
			printf("<%s>\n",curr->cipher->name);
#endif
			}
		}

	if (cipher_list != NULL)
		{
		if (*cipher_list != NULL)
			sk_SSL_CIPHER_free(*cipher_list);
		*cipher_list=ret;
		}

	if (cipher_list_by_id != NULL)
		{
		if (*cipher_list_by_id != NULL)
			sk_SSL_CIPHER_free(*cipher_list_by_id);
		*cipher_list_by_id=sk_SSL_CIPHER_dup(ret);
		}

	if (	(cipher_list_by_id == NULL) ||
		(*cipher_list_by_id == NULL) ||
		(cipher_list == NULL) ||
		(*cipher_list == NULL))
		goto err;
	sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,ssl_cipher_ptr_id_cmp);

	ok=ret;
	ret=NULL;
err:
	if (tmp_str) Free(tmp_str);
	if (ops != NULL) Free(ops);
	if (ret != NULL) sk_SSL_CIPHER_free(ret);
	if (ca_list != NULL) sk_free(ca_list);
	if (list != NULL) Free(list);
	return(ok);
	}

char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
	{
	int is_export,pkl,kl;
	char *ver,*exp;
	char *kx,*au,*enc,*mac;
	unsigned long alg,alg2;
	static char *format="%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s\n";
	
	alg=cipher->algorithms;
	alg2=cipher->algorithm2;

	is_export=SSL_IS_EXPORT(alg);
	pkl=SSL_EXPORT_PKEYLENGTH(alg);
	kl=SSL_EXPORT_KEYLENGTH(alg);
	exp=is_export?" export":"";

	if (alg & SSL_SSLV2)
		ver="SSLv2";
	else if (alg & SSL_SSLV3)
		ver="SSLv3";
	else
		ver="unknown";

	switch (alg&SSL_MKEY_MASK)
		{
	case SSL_kRSA:
		kx=is_export?(pkl == 512 ? "RSA(512)" : "RSA(1024)"):"RSA";
		break;
	case SSL_kDHr:
		kx="DH/RSA";
		break;
	case SSL_kDHd:
		kx="DH/DSS";
		break;
	case SSL_kFZA:
		kx="Fortezza";
		break;
	case SSL_kEDH:
		kx=is_export?(pkl == 512 ? "DH(512)" : "DH(1024)"):"DH";
		break;
	default:
		kx="unknown";
		}

	switch (alg&SSL_AUTH_MASK)
		{
	case SSL_aRSA:
		au="RSA";
		break;
	case SSL_aDSS:
		au="DSS";
		break;
	case SSL_aDH:
		au="DH";
		break;
	case SSL_aFZA:
	case SSL_aNULL:
		au="None";
		break;
	default:
		au="unknown";
		break;
		}

	switch (alg&SSL_ENC_MASK)
		{
	case SSL_DES:
		enc=(is_export && kl == 5)?"DES(40)":"DES(56)";
		break;
	case SSL_3DES:
		enc="3DES(168)";
		break;
	case SSL_RC4:
		enc=is_export?(kl == 5 ? "RC4(40)" : "RC4(56)")
		  :((alg2&SSL2_CF_8_BYTE_ENC)?"RC4(64)":"RC4(128)");
		break;
	case SSL_RC2:
		enc=is_export?(kl == 5 ? "RC2(40)" : "RC2(56)"):"RC2(128)";
		break;
	case SSL_IDEA:
		enc="IDEA(128)";
		break;
	case SSL_eFZA:
		enc="Fortezza";
		break;
	case SSL_eNULL:
		enc="None";
		break;
	default:
		enc="unknown";
		break;
		}

	switch (alg&SSL_MAC_MASK)
		{
	case SSL_MD5:
		mac="MD5";
		break;
	case SSL_SHA1:
		mac="SHA1";
		break;
	default:
		mac="unknown";
		break;
		}

	if (buf == NULL)
		{
		buf=Malloc(128);
		if (buf == NULL) return("Malloc Error");
		}
	else if (len < 128)
		return("Buffer too small");

	sprintf(buf,format,cipher->name,ver,kx,au,enc,mac,exp);
	return(buf);
	}

char *SSL_CIPHER_get_version(SSL_CIPHER *c)
	{
	int i;

	if (c == NULL) return("(NONE)");
	i=(int)(c->id>>24L);
	if (i == 3)
		return("TLSv1/SSLv3");
	else if (i == 2)
		return("SSLv2");
	else
		return("unknown");
	}

/* return the actual cipher being used */
const char *SSL_CIPHER_get_name(SSL_CIPHER *c)
	{
	if (c != NULL)
		return(c->name);
	return("(NONE)");
	}

/* number of bits for symetric cipher */
int SSL_CIPHER_get_bits(SSL_CIPHER *c, int *alg_bits)
	{
	int ret=0,a=0;
	const EVP_CIPHER *enc;
	const EVP_MD *md;
	SSL_SESSION ss;

	if (c != NULL)
		{
		ss.cipher=c;
		if (!ssl_cipher_get_evp(&ss,&enc,&md,NULL))
			return(0);

		a=EVP_CIPHER_key_length(enc)*8;

		if (SSL_C_IS_EXPORT(c))
			{
			ret=SSL_C_EXPORT_KEYLENGTH(c)*8;
			}
		else
			{
			if (c->algorithm2 & SSL2_CF_8_BYTE_ENC)
				ret=64;
			else
				ret=a;
			}
		}

	if (alg_bits != NULL) *alg_bits=a;
	
	return(ret);
	}

SSL_COMP *ssl3_comp_find(STACK_OF(SSL_COMP) *sk, int n)
	{
	SSL_COMP *ctmp;
	int i,nn;

	if ((n == 0) || (sk == NULL)) return(NULL);
	nn=sk_SSL_COMP_num(sk);
	for (i=0; i<nn; i++)
		{
		ctmp=sk_SSL_COMP_value(sk,i);
		if (ctmp->id == n)
			return(ctmp);
		}
	return(NULL);
	}

static int sk_comp_cmp(SSL_COMP **a,SSL_COMP **b)
	{
	return((*a)->id-(*b)->id);
	}

STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)
	{
	return(ssl_comp_methods);
	}

int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
	{
	SSL_COMP *comp;
	STACK_OF(SSL_COMP) *sk;

	comp=(SSL_COMP *)Malloc(sizeof(SSL_COMP));
	comp->id=id;
	comp->method=cm;
	if (ssl_comp_methods == NULL)
		sk=ssl_comp_methods=sk_SSL_COMP_new(sk_comp_cmp);
	else
		sk=ssl_comp_methods;
	if ((sk == NULL) || !sk_SSL_COMP_push(sk,comp))
		{
		SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	else
		return(1);
	}

