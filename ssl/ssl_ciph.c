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
#define SSL_ENC_AES128_IDX	7
#define SSL_ENC_AES256_IDX	8
#define SSL_ENC_NUM_IDX		9

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

#define CIPHER_ADD	1
#define CIPHER_KILL	2
#define CIPHER_DEL	3
#define CIPHER_ORD	4
#define CIPHER_SPECIAL	5

typedef struct cipher_order_st
	{
	SSL_CIPHER *cipher;
	int active;
	int dead;
	struct cipher_order_st *next,*prev;
	} CIPHER_ORDER;

static const SSL_CIPHER cipher_aliases[]={
	/* Don't include eNULL unless specifically enabled.
	 * Similarly, don't include AES in ALL because these ciphers are not yet official. */
	{0,SSL_TXT_ALL, 0,SSL_ALL & ~SSL_eNULL & ~SSL_AES, SSL_ALL ,0,0,0,SSL_ALL,SSL_ALL}, /* must be first */
        {0,SSL_TXT_kKRB5,0,SSL_kKRB5,0,0,0,0,SSL_MKEY_MASK,0},  /* VRS Kerberos5 */
	{0,SSL_TXT_kRSA,0,SSL_kRSA,  0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_kDHr,0,SSL_kDHr,  0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_kDHd,0,SSL_kDHd,  0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_kEDH,0,SSL_kEDH,  0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_kFZA,0,SSL_kFZA,  0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_DH,	0,SSL_DH,    0,0,0,0,SSL_MKEY_MASK,0},
	{0,SSL_TXT_EDH,	0,SSL_EDH,   0,0,0,0,SSL_MKEY_MASK|SSL_AUTH_MASK,0},

	{0,SSL_TXT_aKRB5,0,SSL_aKRB5,0,0,0,0,SSL_AUTH_MASK,0},  /* VRS Kerberos5 */
	{0,SSL_TXT_aRSA,0,SSL_aRSA,  0,0,0,0,SSL_AUTH_MASK,0},
	{0,SSL_TXT_aDSS,0,SSL_aDSS,  0,0,0,0,SSL_AUTH_MASK,0},
	{0,SSL_TXT_aFZA,0,SSL_aFZA,  0,0,0,0,SSL_AUTH_MASK,0},
	{0,SSL_TXT_aNULL,0,SSL_aNULL,0,0,0,0,SSL_AUTH_MASK,0},
	{0,SSL_TXT_aDH, 0,SSL_aDH,   0,0,0,0,SSL_AUTH_MASK,0},
	{0,SSL_TXT_DSS,	0,SSL_DSS,   0,0,0,0,SSL_AUTH_MASK,0},

	{0,SSL_TXT_DES,	0,SSL_DES,   0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_3DES,0,SSL_3DES,  0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_RC4,	0,SSL_RC4,   0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_RC2,	0,SSL_RC2,   0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_IDEA,0,SSL_IDEA,  0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_eNULL,0,SSL_eNULL,0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_eFZA,0,SSL_eFZA,  0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_AES,	0,SSL_AES,   0,0,0,0,SSL_ENC_MASK,0},

	{0,SSL_TXT_MD5,	0,SSL_MD5,   0,0,0,0,SSL_MAC_MASK,0},
	{0,SSL_TXT_SHA1,0,SSL_SHA1,  0,0,0,0,SSL_MAC_MASK,0},
	{0,SSL_TXT_SHA,	0,SSL_SHA,   0,0,0,0,SSL_MAC_MASK,0},

	{0,SSL_TXT_NULL,0,SSL_NULL,  0,0,0,0,SSL_ENC_MASK,0},
	{0,SSL_TXT_KRB5,0,SSL_KRB5,  0,0,0,0,SSL_AUTH_MASK|SSL_MKEY_MASK,0},
	{0,SSL_TXT_RSA,	0,SSL_RSA,   0,0,0,0,SSL_AUTH_MASK|SSL_MKEY_MASK,0},
	{0,SSL_TXT_ADH,	0,SSL_ADH,   0,0,0,0,SSL_AUTH_MASK|SSL_MKEY_MASK,0},
	{0,SSL_TXT_FZA,	0,SSL_FZA,   0,0,0,0,SSL_AUTH_MASK|SSL_MKEY_MASK|SSL_ENC_MASK,0},

	{0,SSL_TXT_SSLV2, 0,SSL_SSLV2, 0,0,0,0,SSL_SSL_MASK,0},
	{0,SSL_TXT_SSLV3, 0,SSL_SSLV3, 0,0,0,0,SSL_SSL_MASK,0},
	{0,SSL_TXT_TLSV1, 0,SSL_TLSV1, 0,0,0,0,SSL_SSL_MASK,0},

	{0,SSL_TXT_EXP   ,0, 0,SSL_EXPORT, 0,0,0,0,SSL_EXP_MASK},
	{0,SSL_TXT_EXPORT,0, 0,SSL_EXPORT, 0,0,0,0,SSL_EXP_MASK},
	{0,SSL_TXT_EXP40, 0, 0, SSL_EXP40, 0,0,0,0,SSL_STRONG_MASK},
	{0,SSL_TXT_EXP56, 0, 0, SSL_EXP56, 0,0,0,0,SSL_STRONG_MASK},
	{0,SSL_TXT_LOW,   0, 0,   SSL_LOW, 0,0,0,0,SSL_STRONG_MASK},
	{0,SSL_TXT_MEDIUM,0, 0,SSL_MEDIUM, 0,0,0,0,SSL_STRONG_MASK},
	{0,SSL_TXT_HIGH,  0, 0,  SSL_HIGH, 0,0,0,0,SSL_STRONG_MASK},
	};

static int init_ciphers=1;

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
	ssl_cipher_methods[SSL_ENC_AES128_IDX]=
	  EVP_get_cipherbyname(SN_aes_128_cbc);
	ssl_cipher_methods[SSL_ENC_AES256_IDX]=
	  EVP_get_cipherbyname(SN_aes_256_cbc);

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
	case SSL_AES:
		switch(c->alg_bits)
			{
		case 128: i=SSL_ENC_AES128_IDX; break;
		case 256: i=SSL_ENC_AES256_IDX; break;
		default: i=-1; break;
			}
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

static unsigned long ssl_cipher_get_disabled(void)
	{
	unsigned long mask;

	mask = SSL_kFZA;
#ifdef OPENSSL_NO_RSA
	mask |= SSL_aRSA|SSL_kRSA;
#endif
#ifdef OPENSSL_NO_DSA
	mask |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
	mask |= SSL_kDHr|SSL_kDHd|SSL_kEDH|SSL_aDH;
#endif
#ifdef OPENSSL_NO_KRB5
	mask |= SSL_kKRB5|SSL_aKRB5;
#endif

#ifdef SSL_FORBID_ENULL
	mask |= SSL_eNULL;
#endif

	mask |= (ssl_cipher_methods[SSL_ENC_DES_IDX ] == NULL) ? SSL_DES :0;
	mask |= (ssl_cipher_methods[SSL_ENC_3DES_IDX] == NULL) ? SSL_3DES:0;
	mask |= (ssl_cipher_methods[SSL_ENC_RC4_IDX ] == NULL) ? SSL_RC4 :0;
	mask |= (ssl_cipher_methods[SSL_ENC_RC2_IDX ] == NULL) ? SSL_RC2 :0;
	mask |= (ssl_cipher_methods[SSL_ENC_IDEA_IDX] == NULL) ? SSL_IDEA:0;
	mask |= (ssl_cipher_methods[SSL_ENC_eFZA_IDX] == NULL) ? SSL_eFZA:0;
	mask |= (ssl_cipher_methods[SSL_ENC_AES128_IDX] == NULL) ? SSL_AES:0;

	mask |= (ssl_digest_methods[SSL_MD_MD5_IDX ] == NULL) ? SSL_MD5 :0;
	mask |= (ssl_digest_methods[SSL_MD_SHA1_IDX] == NULL) ? SSL_SHA1:0;

	return(mask);
	}

static void ssl_cipher_collect_ciphers(const SSL_METHOD *ssl_method,
		int num_of_ciphers, unsigned long mask, CIPHER_ORDER *list,
		CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
	{
	int i, list_num;
	SSL_CIPHER *c;

	/*
	 * We have num_of_ciphers descriptions compiled in, depending on the
	 * method selected (SSLv2 and/or SSLv3, TLSv1 etc).
	 * These will later be sorted in a linked list with at most num
	 * entries.
	 */

	/* Get the initial list of ciphers */
	list_num = 0;	/* actual count of ciphers */
	for (i = 0; i < num_of_ciphers; i++)
		{
		c = ssl_method->get_cipher(i);
		/* drop those that use any of that is not available */
		if ((c != NULL) && c->valid && !(c->algorithms & mask))
			{
			list[list_num].cipher = c;
			list[list_num].next = NULL;
			list[list_num].prev = NULL;
			list[list_num].active = 0;
			list_num++;
#ifdef KSSL_DEBUG
			printf("\t%d: %s %lx %lx\n",i,c->name,c->id,c->algorithms);
#endif	/* KSSL_DEBUG */
			/*
			if (!sk_push(ca_list,(char *)c)) goto err;
			*/
			}
		}

	/*
	 * Prepare linked list from list entries
	 */	
	for (i = 1; i < list_num - 1; i++)
		{
		list[i].prev = &(list[i-1]);
		list[i].next = &(list[i+1]);
		}
	if (list_num > 0)
		{
		(*head_p) = &(list[0]);
		(*head_p)->prev = NULL;
		(*head_p)->next = &(list[1]);
		(*tail_p) = &(list[list_num - 1]);
		(*tail_p)->prev = &(list[list_num - 2]);
		(*tail_p)->next = NULL;
		}
	}

static void ssl_cipher_collect_aliases(SSL_CIPHER **ca_list,
			int num_of_group_aliases, unsigned long mask,
			CIPHER_ORDER *head)
	{
	CIPHER_ORDER *ciph_curr;
	SSL_CIPHER **ca_curr;
	int i;

	/*
	 * First, add the real ciphers as already collected
	 */
	ciph_curr = head;
	ca_curr = ca_list;
	while (ciph_curr != NULL)
		{
		*ca_curr = ciph_curr->cipher;
		ca_curr++;
		ciph_curr = ciph_curr->next;
		}

	/*
	 * Now we add the available ones from the cipher_aliases[] table.
	 * They represent either an algorithm, that must be fully
	 * supported (not match any bit in mask) or represent a cipher
	 * strength value (will be added in any case because algorithms=0).
	 */
	for (i = 0; i < num_of_group_aliases; i++)
		{
		if ((i == 0) ||		/* always fetch "ALL" */
		    !(cipher_aliases[i].algorithms & mask))
			{
			*ca_curr = (SSL_CIPHER *)(cipher_aliases + i);
			ca_curr++;
			}
		}

	*ca_curr = NULL;	/* end of list */
	}

static void ssl_cipher_apply_rule(unsigned long algorithms, unsigned long mask,
		unsigned long algo_strength, unsigned long mask_strength,
		int rule, int strength_bits, CIPHER_ORDER *list,
		CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
	{
	CIPHER_ORDER *head, *tail, *curr, *curr2, *tail2;
	SSL_CIPHER *cp;
	unsigned long ma, ma_s;

#ifdef CIPHER_DEBUG
	printf("Applying rule %d with %08lx %08lx %08lx %08lx (%d)\n",
		rule, algorithms, mask, algo_strength, mask_strength,
		strength_bits);
#endif

	curr = head = *head_p;
	curr2 = head;
	tail2 = tail = *tail_p;
	for (;;)
		{
		if ((curr == NULL) || (curr == tail2)) break;
		curr = curr2;
		curr2 = curr->next;

		cp = curr->cipher;

		/*
		 * Selection criteria is either the number of strength_bits
		 * or the algorithm used.
		 */
		if (strength_bits == -1)
			{
			ma = mask & cp->algorithms;
			ma_s = mask_strength & cp->algo_strength;

#ifdef CIPHER_DEBUG
			printf("\nName: %s:\nAlgo = %08lx Algo_strength = %08lx\nMask = %08lx Mask_strength %08lx\n", cp->name, cp->algorithms, cp->algo_strength, mask, mask_strength);
			printf("ma = %08lx ma_s %08lx, ma&algo=%08lx, ma_s&algos=%08lx\n", ma, ma_s, ma&algorithms, ma_s&algo_strength);
#endif
			/*
			 * Select: if none of the mask bit was met from the
			 * cipher or not all of the bits were met, the
			 * selection does not apply.
			 */
			if (((ma == 0) && (ma_s == 0)) ||
			    ((ma & algorithms) != ma) ||
			    ((ma_s & algo_strength) != ma_s))
				continue; /* does not apply */
			}
		else if (strength_bits != cp->strength_bits)
			continue;	/* does not apply */

#ifdef CIPHER_DEBUG
		printf("Action = %d\n", rule);
#endif

		/* add the cipher if it has not been added yet. */
		if (rule == CIPHER_ADD)
			{
			if (!curr->active)
				{
				ll_append_tail(&head, curr, &tail);
				curr->active = 1;
				}
			}
		/* Move the added cipher to this location */
		else if (rule == CIPHER_ORD)
			{
			if (curr->active)
				{
				ll_append_tail(&head, curr, &tail);
				}
			}
		else if	(rule == CIPHER_DEL)
			curr->active = 0;
		else if (rule == CIPHER_KILL)
			{
			if (head == curr)
				head = curr->next;
			else
				curr->prev->next = curr->next;
			if (tail == curr)
				tail = curr->prev;
			curr->active = 0;
			if (curr->next != NULL)
				curr->next->prev = curr->prev;
			if (curr->prev != NULL)
				curr->prev->next = curr->next;
			curr->next = NULL;
			curr->prev = NULL;
			}
		}

	*head_p = head;
	*tail_p = tail;
	}

static int ssl_cipher_strength_sort(CIPHER_ORDER *list, CIPHER_ORDER **head_p,
				     CIPHER_ORDER **tail_p)
	{
	int max_strength_bits, i, *number_uses;
	CIPHER_ORDER *curr;

	/*
	 * This routine sorts the ciphers with descending strength. The sorting
	 * must keep the pre-sorted sequence, so we apply the normal sorting
	 * routine as '+' movement to the end of the list.
	 */
	max_strength_bits = 0;
	curr = *head_p;
	while (curr != NULL)
		{
		if (curr->active &&
		    (curr->cipher->strength_bits > max_strength_bits))
		    max_strength_bits = curr->cipher->strength_bits;
		curr = curr->next;
		}

	number_uses = OPENSSL_malloc((max_strength_bits + 1) * sizeof(int));
	if (!number_uses)
	{
		SSLerr(SSL_F_SSL_CIPHER_STRENGTH_SORT,ERR_R_MALLOC_FAILURE);
		return(0);
	}
	memset(number_uses, 0, (max_strength_bits + 1) * sizeof(int));

	/*
	 * Now find the strength_bits values actually used
	 */
	curr = *head_p;
	while (curr != NULL)
		{
		if (curr->active)
			number_uses[curr->cipher->strength_bits]++;
		curr = curr->next;
		}
	/*
	 * Go through the list of used strength_bits values in descending
	 * order.
	 */
	for (i = max_strength_bits; i >= 0; i--)
		if (number_uses[i] > 0)
			ssl_cipher_apply_rule(0, 0, 0, 0, CIPHER_ORD, i,
					list, head_p, tail_p);

	OPENSSL_free(number_uses);
	return(1);
	}

static int ssl_cipher_process_rulestr(const char *rule_str,
		CIPHER_ORDER *list, CIPHER_ORDER **head_p,
		CIPHER_ORDER **tail_p, SSL_CIPHER **ca_list)
	{
	unsigned long algorithms, mask, algo_strength, mask_strength;
	const char *l, *start, *buf;
	int j, multi, found, rule, retval, ok, buflen;
	char ch;

	retval = 1;
	l = rule_str;
	for (;;)
		{
		ch = *l;

		if (ch == '\0')
			break;		/* done */
		if (ch == '-')
			{ rule = CIPHER_DEL; l++; }
		else if (ch == '+')
			{ rule = CIPHER_ORD; l++; }
		else if (ch == '!')
			{ rule = CIPHER_KILL; l++; }
		else if (ch == '@')
			{ rule = CIPHER_SPECIAL; l++; }
		else
			{ rule = CIPHER_ADD; }

		if (ITEM_SEP(ch))
			{
			l++;
			continue;
			}

		algorithms = mask = algo_strength = mask_strength = 0;

		start=l;
		for (;;)
			{
			ch = *l;
			buf = l;
			buflen = 0;
#ifndef CHARSET_EBCDIC
			while (	((ch >= 'A') && (ch <= 'Z')) ||
				((ch >= '0') && (ch <= '9')) ||
				((ch >= 'a') && (ch <= 'z')) ||
				 (ch == '-'))
#else
			while (	isalnum(ch) || (ch == '-'))
#endif
				 {
				 ch = *(++l);
				 buflen++;
				 }

			if (buflen == 0)
				{
				/*
				 * We hit something we cannot deal with,
				 * it is no command or separator nor
				 * alphanumeric, so we call this an error.
				 */
				SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
				       SSL_R_INVALID_COMMAND);
				retval = found = 0;
				l++;
				break;
				}

			if (rule == CIPHER_SPECIAL)
				{
				found = 0; /* unused -- avoid compiler warning */
				break;	/* special treatment */
				}

			/* check for multi-part specification */
			if (ch == '+')
				{
				multi=1;
				l++;
				}
			else
				multi=0;

			/*
			 * Now search for the cipher alias in the ca_list. Be careful
			 * with the strncmp, because the "buflen" limitation
			 * will make the rule "ADH:SOME" and the cipher
			 * "ADH-MY-CIPHER" look like a match for buflen=3.
			 * So additionally check whether the cipher name found
			 * has the correct length. We can save a strlen() call:
			 * just checking for the '\0' at the right place is
			 * sufficient, we have to strncmp() anyway.
			 */
			 j = found = 0;
			 while (ca_list[j])
				{
				if ((ca_list[j]->name[buflen] == '\0') &&
				    !strncmp(buf, ca_list[j]->name, buflen))
					{
					found = 1;
					break;
					}
				else
					j++;
				}
			if (!found)
				break;	/* ignore this entry */

			algorithms |= ca_list[j]->algorithms;
			mask |= ca_list[j]->mask;
			algo_strength |= ca_list[j]->algo_strength;
			mask_strength |= ca_list[j]->mask_strength;

			if (!multi) break;
			}

		/*
		 * Ok, we have the rule, now apply it
		 */
		if (rule == CIPHER_SPECIAL)
			{	/* special command */
			ok = 0;
			if ((buflen == 8) &&
				!strncmp(buf, "STRENGTH", 8))
				ok = ssl_cipher_strength_sort(list,
					head_p, tail_p);
			else
				SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
					SSL_R_INVALID_COMMAND);
			if (ok == 0)
				retval = 0;
			/*
			 * We do not support any "multi" options
			 * together with "@", so throw away the
			 * rest of the command, if any left, until
			 * end or ':' is found.
			 */
			while ((*l != '\0') && ITEM_SEP(*l))
				l++;
			}
		else if (found)
			{
			ssl_cipher_apply_rule(algorithms, mask,
				algo_strength, mask_strength, rule, -1,
				list, head_p, tail_p);
			}
		else
			{
			while ((*l != '\0') && ITEM_SEP(*l))
				l++;
			}
		if (*l == '\0') break; /* done */
		}

	return(retval);
	}

STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *ssl_method,
		STACK_OF(SSL_CIPHER) **cipher_list,
		STACK_OF(SSL_CIPHER) **cipher_list_by_id,
		const char *rule_str)
	{
	int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases;
	unsigned long disabled_mask;
	STACK_OF(SSL_CIPHER) *cipherstack;
	const char *rule_p;
	CIPHER_ORDER *list = NULL, *head = NULL, *tail = NULL, *curr;
	SSL_CIPHER **ca_list = NULL;

	/*
	 * Return with error if nothing to do.
	 */
	if (rule_str == NULL) return(NULL);

	if (init_ciphers) load_ciphers();

	/*
	 * To reduce the work to do we only want to process the compiled
	 * in algorithms, so we first get the mask of disabled ciphers.
	 */
	disabled_mask = ssl_cipher_get_disabled();

	/*
	 * Now we have to collect the available ciphers from the compiled
	 * in ciphers. We cannot get more than the number compiled in, so
	 * it is used for allocation.
	 */
	num_of_ciphers = ssl_method->num_ciphers();
#ifdef KSSL_DEBUG
	printf("ssl_create_cipher_list() for %d ciphers\n", num_of_ciphers);
#endif    /* KSSL_DEBUG */
	list = (CIPHER_ORDER *)OPENSSL_malloc(sizeof(CIPHER_ORDER) * num_of_ciphers);
	if (list == NULL)
		{
		SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
		return(NULL);	/* Failure */
		}

	ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers, disabled_mask,
				   list, &head, &tail);

	/*
	 * We also need cipher aliases for selecting based on the rule_str.
	 * There might be two types of entries in the rule_str: 1) names
	 * of ciphers themselves 2) aliases for groups of ciphers.
	 * For 1) we need the available ciphers and for 2) the cipher
	 * groups of cipher_aliases added together in one list (otherwise
	 * we would be happy with just the cipher_aliases table).
	 */
	num_of_group_aliases = sizeof(cipher_aliases) / sizeof(SSL_CIPHER);
	num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
	ca_list =
		(SSL_CIPHER **)OPENSSL_malloc(sizeof(SSL_CIPHER *) * num_of_alias_max);
	if (ca_list == NULL)
		{
		OPENSSL_free(list);
		SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
		return(NULL);	/* Failure */
		}
	ssl_cipher_collect_aliases(ca_list, num_of_group_aliases, disabled_mask,
				   head);

	/*
	 * If the rule_string begins with DEFAULT, apply the default rule
	 * before using the (possibly available) additional rules.
	 */
	ok = 1;
	rule_p = rule_str;
	if (strncmp(rule_str,"DEFAULT",7) == 0)
		{
		ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
			list, &head, &tail, ca_list);
		rule_p += 7;
		if (*rule_p == ':')
			rule_p++;
		}

	if (ok && (strlen(rule_p) > 0))
		ok = ssl_cipher_process_rulestr(rule_p, list, &head, &tail,
						ca_list);

	OPENSSL_free(ca_list);	/* Not needed anymore */

	if (!ok)
		{	/* Rule processing failure */
		OPENSSL_free(list);
		return(NULL);
		}
	/*
	 * Allocate new "cipherstack" for the result, return with error
	 * if we cannot get one.
	 */
	if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL)
		{
		OPENSSL_free(list);
		return(NULL);
		}

	/*
	 * The cipher selection for the list is done. The ciphers are added
	 * to the resulting precedence to the STACK_OF(SSL_CIPHER).
	 */
	for (curr = head; curr != NULL; curr = curr->next)
		{
		if (curr->active)
			{
			sk_SSL_CIPHER_push(cipherstack, curr->cipher);
#ifdef CIPHER_DEBUG
			printf("<%s>\n",curr->cipher->name);
#endif
			}
		}
	OPENSSL_free(list);	/* Not needed any longer */

	/*
	 * The following passage is a little bit odd. If pointer variables
	 * were supplied to hold STACK_OF(SSL_CIPHER) return information,
	 * the old memory pointed to is free()ed. Then, however, the
	 * cipher_list entry will be assigned just a copy of the returned
	 * cipher stack. For cipher_list_by_id a copy of the cipher stack
	 * will be created. See next comment...
	 */
	if (cipher_list != NULL)
		{
		if (*cipher_list != NULL)
			sk_SSL_CIPHER_free(*cipher_list);
		*cipher_list = cipherstack;
		}

	if (cipher_list_by_id != NULL)
		{
		if (*cipher_list_by_id != NULL)
			sk_SSL_CIPHER_free(*cipher_list_by_id);
		*cipher_list_by_id = sk_SSL_CIPHER_dup(cipherstack);
		}

	/*
	 * Now it is getting really strange. If something failed during
	 * the previous pointer assignment or if one of the pointers was
	 * not requested, the error condition is met. That might be
	 * discussable. The strange thing is however that in this case
	 * the memory "ret" pointed to is "free()ed" and hence the pointer
	 * cipher_list becomes wild. The memory reserved for
	 * cipher_list_by_id however is not "free()ed" and stays intact.
	 */
	if (	(cipher_list_by_id == NULL) ||
		(*cipher_list_by_id == NULL) ||
		(cipher_list == NULL) ||
		(*cipher_list == NULL))
		{
		sk_SSL_CIPHER_free(cipherstack);
		return(NULL);
		}

	sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,ssl_cipher_ptr_id_cmp);

	return(cipherstack);
	}

char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
	{
	int is_export,pkl,kl;
	char *ver,*exp;
	char *kx,*au,*enc,*mac;
	unsigned long alg,alg2,alg_s;
#ifdef KSSL_DEBUG
	static char *format="%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s AL=%lx\n";
#else
	static char *format="%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s\n";
#endif /* KSSL_DEBUG */

	alg=cipher->algorithms;
	alg_s=cipher->algo_strength;
	alg2=cipher->algorithm2;

	is_export=SSL_C_IS_EXPORT(cipher);
	pkl=SSL_C_EXPORT_PKEYLENGTH(cipher);
	kl=SSL_C_EXPORT_KEYLENGTH(cipher);
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
        case SSL_kKRB5:         /* VRS */
        case SSL_KRB5:          /* VRS */
            kx="KRB5";
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
        case SSL_aKRB5:         /* VRS */
        case SSL_KRB5:          /* VRS */
            au="KRB5";
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
	case SSL_AES:
		switch(cipher->strength_bits)
			{
		case 128: enc="AESdraft(128)"; break;
		case 192: enc="AESdraft(192)"; break;
		case 256: enc="AESdraft(256)"; break;
		default: enc="AESdraft(?""?""?)"; break;
			}
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
		len=128;
		buf=OPENSSL_malloc(len);
		if (buf == NULL) return("OPENSSL_malloc Error");
		}
	else if (len < 128)
		return("Buffer too small");

#ifdef KSSL_DEBUG
	BIO_snprintf(buf,len,format,cipher->name,ver,kx,au,enc,mac,exp,alg);
#else
	BIO_snprintf(buf,len,format,cipher->name,ver,kx,au,enc,mac,exp);
#endif /* KSSL_DEBUG */
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

/* number of bits for symmetric cipher */
int SSL_CIPHER_get_bits(SSL_CIPHER *c, int *alg_bits)
	{
	int ret=0;

	if (c != NULL)
		{
		if (alg_bits != NULL) *alg_bits = c->alg_bits;
		ret = c->strength_bits;
		}
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

static int sk_comp_cmp(const SSL_COMP * const *a,
			const SSL_COMP * const *b)
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

        if (cm == NULL || cm->type == NID_undef)
                return 1;

	MemCheck_off();
	comp=(SSL_COMP *)OPENSSL_malloc(sizeof(SSL_COMP));
	comp->id=id;
	comp->method=cm;
	if (ssl_comp_methods == NULL)
		sk=ssl_comp_methods=sk_SSL_COMP_new(sk_comp_cmp);
	else
		sk=ssl_comp_methods;
	if ((sk == NULL) || !sk_SSL_COMP_push(sk,comp))
		{
		MemCheck_on();
		SSLerr(SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	else
		{
		MemCheck_on();
		return(1);
		}
	}
