/* crypto/asn1/asn1.h */
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

#ifndef HEADER_ASN1_H
#define HEADER_ASN1_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <time.h>
#include "bn.h"
#include "stack.h"

#define V_ASN1_UNIVERSAL		0x00
#define	V_ASN1_APPLICATION		0x40
#define V_ASN1_CONTEXT_SPECIFIC		0x80
#define V_ASN1_PRIVATE			0xc0

#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMATIVE_TAG		0x1f

#define V_ASN1_APP_CHOOSE		-2	/* let the recipent choose */

#define V_ASN1_UNDEF			-1
#define V_ASN1_EOC			0
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2+0x100)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_OBJECT_DESCRIPTOR	7
#define V_ASN1_EXTERNAL			8
#define V_ASN1_REAL			9
#define V_ASN1_ENUMERATED		10	/* microsoft weirdness */
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET			17
#define V_ASN1_NUMERICSTRING		18	/**/
#define V_ASN1_PRINTABLESTRING		19
#define V_ASN1_T61STRING		20
#define V_ASN1_TELETEXSTRING		20	/* alias */
#define V_ASN1_VIDEOTEXSTRING		21	/**/
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME		24	/**/
#define V_ASN1_GRAPHICSTRING		25	/**/
#define V_ASN1_ISO64STRING		26	/**/
#define V_ASN1_VISIBLESTRING		26	/* alias */
#define V_ASN1_GENERALSTRING		27	/**/
#define V_ASN1_UNIVERSALSTRING		28	/**/
#define V_ASN1_BMPSTRING		30

/* For use with d2i_ASN1_type_bytes() */
#define B_ASN1_NUMERICSTRING	0x0001
#define B_ASN1_PRINTABLESTRING	0x0002
#define B_ASN1_T61STRING	0x0004
#define B_ASN1_VIDEOTEXSTRING	0x0008
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_GRAPHICSTRING	0x0020
#define B_ASN1_ISO64STRING	0x0040
#define B_ASN1_GENERALSTRING	0x0080
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_OCTET_STRING	0x0200
#define B_ASN1_BIT_STRING	0x0400
#define B_ASN1_BMPSTRING	0x0800
#define B_ASN1_UNKNOWN		0x1000

#ifndef DEBUG

#define ASN1_INTEGER		ASN1_STRING
#define ASN1_BIT_STRING		ASN1_STRING
#define ASN1_OCTET_STRING	ASN1_STRING
#define ASN1_PRINTABLESTRING	ASN1_STRING
#define ASN1_T61STRING		ASN1_STRING
#define ASN1_IA5STRING		ASN1_STRING
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_GENERALSTRING	ASN1_STRING
#define ASN1_UNIVERSALSTRING	ASN1_STRING
#define ASN1_BMPSTRING		ASN1_STRING

#else

typedef struct asn1_integer_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_INTEGER;

typedef struct asn1_bit_string_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_BIT_STRING;

typedef struct asn1_octet_string_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_OCTET_STRING;

typedef struct asn1_printablestring_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_PRINTABLESTRING;

typedef struct asn1_t61string_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_T61STRING;

typedef struct asn1_ia5string_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_IA5STRING;

typedef struct asn1_generalstring_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_GENERALSTRING;

typedef struct asn1_universalstring_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_UNIVERSALSTRING;

typedef struct asn1_bmpstring_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_BMPSTRING;

typedef struct asn1_utctime_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_UTCTIME;

typedef struct asn1_generalizedtime_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_GENERALIZEDTIME;

#endif

typedef struct asn1_ctx_st
	{
	unsigned char *p;/* work char pointer */
	int eos;	/* end of sequence read for indefinite encoding */
	int error;	/* error code to use when returning an error */
	int inf;	/* constructed if 0x20, indefinite is 0x21 */
	int tag;	/* tag from last 'get object' */
	int xclass;	/* class from last 'get object' */
	long slen;	/* length of last 'get object' */
	unsigned char *max; /* largest value of p alowed */
	unsigned char *q;/* temporary variable */
	unsigned char **pp;/* variable */
	} ASN1_CTX;

/* These are used internally in the ASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed */
#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_CRITICAL	 0x02	/* critical x509v3 object id */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
typedef struct asn1_object_st
	{
	char *sn,*ln;
	int nid;
	int length;
	unsigned char *data;
	int flags;	/* Should we free this one */
	} ASN1_OBJECT;

/* This is the base type that holds just about everything :-) */
typedef struct asn1_string_st
	{
	int length;
	int type;
	unsigned char *data;
	} ASN1_STRING;

typedef struct asn1_type_st
	{
	int type;
	union	{
		char *ptr;
		ASN1_STRING *		asn1_string;
		ASN1_OBJECT *		object;
		ASN1_INTEGER *		integer;
		ASN1_BIT_STRING *	bit_string;
		ASN1_OCTET_STRING *	octet_string;
		ASN1_PRINTABLESTRING *	printablestring;
		ASN1_T61STRING *	t61string;
		ASN1_IA5STRING *	ia5string;
		ASN1_GENERALSTRING *	generalstring;
		ASN1_BMPSTRING *	bmpstring;
		ASN1_UNIVERSALSTRING *	universalstring;
		ASN1_UTCTIME *		utctime;
		ASN1_GENERALIZEDTIME *	generalizedtime;
		/* set and sequence are left complete and still
		 * contain the set or sequence bytes */
		ASN1_STRING *		set;
		ASN1_STRING *		sequence;
		} value;
	} ASN1_TYPE;

typedef struct asn1_method_st
	{
	int (*i2d)();
	char *(*d2i)();
	char *(*create)();
	void (*destroy)();
	} ASN1_METHOD;

/* This is used when parsing some Netscape objects */
typedef struct asn1_header_st
	{
	ASN1_OCTET_STRING *header;
	char *data;
	ASN1_METHOD *meth;
	} ASN1_HEADER;

#define ASN1_STRING_length(x)	((x)->length)
#define ASN1_STRING_type(x)	((x)->type)
#define ASN1_STRING_data(x)	((x)->data)

/* Macros for string operations */
#define ASN1_BIT_STRING_new()	(ASN1_BIT_STRING *)\
		ASN1_STRING_type_new(V_ASN1_BIT_STRING)
#define ASN1_BIT_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define ASN1_BIT_STRING_dup(a) (ASN1_BIT_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define ASN1_BIT_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define ASN1_BIT_STRING_set(a,b,c) ASN1_STRING_set((ASN1_STRING *)a,b,c)
/* i2d_ASN1_BIT_STRING() is a function */
/* d2i_ASN1_BIT_STRING() is a function */

#define ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)
#define ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)
#define ASN1_INTEGER_dup(a) (ASN1_INTEGER *)ASN1_STRING_dup((ASN1_STRING *)a)
#define ASN1_INTEGER_cmp(a,b)	ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
/* ASN1_INTEGER_set() is a function, also see BN_to_ASN1_INTEGER() */
/* ASN1_INTEGER_get() is a function, also see ASN1_INTEGER_to_BN() */
/* i2d_ASN1_INTEGER() is a function */
/* d2i_ASN1_INTEGER() is a function */

#define ASN1_OCTET_STRING_new()	(ASN1_OCTET_STRING *)\
		ASN1_STRING_type_new(V_ASN1_OCTET_STRING)
#define ASN1_OCTET_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define ASN1_OCTET_STRING_dup(a) (ASN1_OCTET_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define ASN1_OCTET_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define ASN1_OCTET_STRING_set(a,b,c)	ASN1_STRING_set((ASN1_STRING *)a,b,c)
#define ASN1_OCTET_STRING_print(a,b)	ASN1_STRING_print(a,(ASN1_STRING *)b)
#define M_i2d_ASN1_OCTET_STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_OCTET_STRING,\
		V_ASN1_OCTET_STRING)
/* d2i_ASN1_OCTET_STRING() is a function */

#define ASN1_PRINTABLE_new()	ASN1_STRING_type_new(V_ASN1_T61STRING)
#define ASN1_PRINTABLE_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_PRINTABLE(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
		pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_PRINTABLE(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_PRINTABLESTRING| \
			B_ASN1_T61STRING| \
			B_ASN1_IA5STRING| \
			B_ASN1_BIT_STRING| \
			B_ASN1_UNIVERSALSTRING|\
			B_ASN1_BMPSTRING|\
			B_ASN1_UNKNOWN)

#define ASN1_PRINTABLESTRING_new() (ASN1_PRINTABLESTRING_STRING *)\
		ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
#define ASN1_PRINTABLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_PRINTABLESTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_PRINTABLESTRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_PRINTABLESTRING(a,pp,l) \
		(ASN1_PRINTABLESTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_PRINTABLESTRING)

#define ASN1_T61STRING_new()	(ASN1_T61STRING_STRING *)\
		ASN1_STRING_type_new(V_ASN1_T61STRING)
#define ASN1_T61STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_T61STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_T61STRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_T61STRING(a,pp,l) \
		(ASN1_T61STRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_T61STRING)

#define ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)
#define ASN1_IA5STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_IA5STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_IA5STRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_IA5STRING(a,pp,l) \
		(ASN1_IA5STRING *)d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l,\
			B_ASN1_IA5STRING)

#define ASN1_UTCTIME_new()	(ASN1_UTCTIME *)\
		ASN1_STRING_type_new(V_ASN1_UTCTIME)
#define ASN1_UTCTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define ASN1_UTCTIME_dup(a) (ASN1_UTCTIME *)ASN1_STRING_dup((ASN1_STRING *)a)
/* i2d_ASN1_UTCTIME() is a function */
/* d2i_ASN1_UTCTIME() is a function */
/* ASN1_UTCTIME_set() is a function */
/* ASN1_UTCTIME_check() is a function */

#define ASN1_GENERALIZEDTIME_new()	(ASN1_GENERALIZEDTIME *)\
		ASN1_STRING_type_new(V_ASN1_GENERALIZEDTIME)
#define ASN1_GENERALIZEDTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define ASN1_GENERALIZEDTIME_dup(a) (ASN1_UTCTIME *)ASN1_STRING_dup(\
	(ASN1_STRING *)a)
/* DOES NOT EXIST YET i2d_ASN1_GENERALIZEDTIME() is a function */
/* DOES NOT EXIST YET d2i_ASN1_GENERALIZEDTIME() is a function */
/* DOES NOT EXIST YET ASN1_GENERALIZEDTIME_set() is a function */
/* DOES NOT EXIST YET ASN1_GENERALIZEDTIME_check() is a function */

#define ASN1_GENERALSTRING_new()	(ASN1_GENERALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_GENERALSTRING)
#define ASN1_GENERALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_GENERALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_GENERALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_GENERALSTRING(a,pp,l) \
		(ASN1_GENERALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_GENERALSTRING)

#define ASN1_UNIVERSALSTRING_new()	(ASN1_UNIVERSALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_UNIVERSALSTRING)
#define ASN1_UNIVERSALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_UNIVERSALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_UNIVERSALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_UNIVERSALSTRING(a,pp,l) \
		(ASN1_UNIVERSALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_UNIVERSALSTRING)

#define ASN1_BMPSTRING_new()	(ASN1_BMPSTRING *)\
		ASN1_STRING_type_new(V_ASN1_BMPSTRING)
#define ASN1_BMPSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_BMPSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_BMPSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_BMPSTRING(a,pp,l) \
		(ASN1_BMPSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_BMPSTRING)

#ifndef NOPROTO
ASN1_TYPE *	ASN1_TYPE_new(void );
void		ASN1_TYPE_free(ASN1_TYPE *a);
int		i2d_ASN1_TYPE(ASN1_TYPE *a,unsigned char **pp);
ASN1_TYPE *	d2i_ASN1_TYPE(ASN1_TYPE **a,unsigned char **pp,long length);
int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, char *value);

ASN1_OBJECT *	ASN1_OBJECT_new(void );
void		ASN1_OBJECT_free(ASN1_OBJECT *a);
int		i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,unsigned char **pp,
			long length);

ASN1_STRING *	ASN1_STRING_new(void );
void		ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_dup(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_type_new(int type );
int 		ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b);
int 		ASN1_STRING_set(ASN1_STRING *str,unsigned char *data, int len);

int		i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,unsigned char **pp,
			long length);
int		ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int		ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);


int		i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int 		d2i_ASN1_BOOLEAN(int *a,unsigned char **pp,long length);

int		i2d_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a,unsigned char **pp,
			long length);

int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, char *str); 

int		i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a,unsigned char **pp);
ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a,
			unsigned char **pp,long length);

int i2d_ASN1_PRINTABLE(ASN1_STRING *a,unsigned char **pp);
ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a,
	unsigned char **pp, long l);
ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a,
	unsigned char **pp, long l);

ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a,
	unsigned char **pp, long l);
int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a,unsigned char **pp);
ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a,
	unsigned char **pp, long l);

int		i2d_ASN1_UTCTIME(ASN1_UTCTIME *a,unsigned char **pp);
ASN1_UTCTIME *	d2i_ASN1_UTCTIME(ASN1_UTCTIME **a,unsigned char **pp,
			long length);

int		i2d_ASN1_SET(STACK *a, unsigned char **pp,
			int (*func)(), int ex_tag, int ex_class);
STACK *		d2i_ASN1_SET(STACK **a, unsigned char **pp, long length,
			char *(*func)(), int ex_tag, int ex_class);

#ifdef HEADER_BIO_H
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);
#endif
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out,int olen, char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
	char *sn, char *ln);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
int ASN1_PRINTABLE_type(unsigned char *s, int max);

int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass);
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, unsigned char **pp,
	long length, int Ptag, int Pclass);
/* type is one or more of the B_ASN1_ values. */
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,unsigned char **pp,
		long length,int type);

/* PARSING */
int asn1_Finish(ASN1_CTX *c);

/* SPECIALS */
int ASN1_get_object(unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p,long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
	int tag, int xclass);
int ASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
char *ASN1_dup(int (*i2d)(),char *(*d2i)(),char *x);

#ifndef NO_FP_API
char *ASN1_d2i_fp(char *(*xnew)(),char *(*d2i)(),FILE *fp,unsigned char **x);
int ASN1_i2d_fp(int (*i2d)(),FILE *out,unsigned char *x);
#endif

#ifdef HEADER_BIO_H
char *ASN1_d2i_bio(char *(*xnew)(),char *(*d2i)(),BIO *bp,unsigned char **x);
int ASN1_i2d_bio(int (*i2d)(),BIO *out,unsigned char *x);
int ASN1_UTCTIME_print(BIO *fp,ASN1_UTCTIME *a);
int ASN1_STRING_print(BIO *bp,ASN1_STRING *v);
int ASN1_parse(BIO *bp,unsigned char *pp,long len,int indent);
#endif

/* Used to load and write netscape format cert/key */
int i2d_ASN1_HEADER(ASN1_HEADER *a,unsigned char **pp);
ASN1_HEADER *d2i_ASN1_HEADER(ASN1_HEADER **a,unsigned char **pp, long length);
ASN1_HEADER *ASN1_HEADER_new(void );
void ASN1_HEADER_free(ASN1_HEADER *a);

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

void ERR_load_ASN1_strings(void);

/* Not used that much at this point, except for the first two */
ASN1_METHOD *X509_asn1_meth(void);
ASN1_METHOD *RSAPrivateKey_asn1_meth(void);
ASN1_METHOD *ASN1_IA5STRING_asn1_meth(void);
ASN1_METHOD *ASN1_BIT_STRING_asn1_meth(void);

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,
	unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,
	unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
	unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,
	unsigned char *data, int max_len);

#else

ASN1_TYPE *	ASN1_TYPE_new();
void		ASN1_TYPE_free();
int		i2d_ASN1_TYPE();
ASN1_TYPE *	d2i_ASN1_TYPE();
int ASN1_TYPE_get();
void ASN1_TYPE_set();

ASN1_OBJECT *	ASN1_OBJECT_new();
void		ASN1_OBJECT_free();
int		i2d_ASN1_OBJECT();
ASN1_OBJECT *	d2i_ASN1_OBJECT();
ASN1_STRING *	ASN1_STRING_new();
void		ASN1_STRING_free();
ASN1_STRING *	ASN1_STRING_dup();
ASN1_STRING *	ASN1_STRING_type_new();
int 		ASN1_STRING_cmp();
int 		ASN1_STRING_set();
int		i2d_ASN1_BIT_STRING();
ASN1_BIT_STRING *d2i_ASN1_BIT_STRING();
int		ASN1_BIT_STRING_set_bit();
int		ASN1_BIT_STRING_get_bit();
int		i2d_ASN1_BOOLEAN();
int 		d2i_ASN1_BOOLEAN();
int		i2d_ASN1_INTEGER();
ASN1_INTEGER *d2i_ASN1_INTEGER();
int ASN1_UTCTIME_check();
ASN1_UTCTIME *ASN1_UTCTIME_set();
int ASN1_UTCTIME_set_string();
int		i2d_ASN1_OCTET_STRING();
ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING();
int i2d_ASN1_PRINTABLE();
ASN1_STRING *d2i_ASN1_PRINTABLE();
ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING();
ASN1_T61STRING *d2i_ASN1_T61STRING();
int i2d_ASN1_IA5STRING();
ASN1_IA5STRING *d2i_ASN1_IA5STRING();
int		i2d_ASN1_UTCTIME();
ASN1_UTCTIME *	d2i_ASN1_UTCTIME();
int		i2d_ASN1_SET();
STACK *		d2i_ASN1_SET();
int a2d_ASN1_OBJECT();
ASN1_OBJECT *ASN1_OBJECT_create();
int ASN1_INTEGER_set();
long ASN1_INTEGER_get();
ASN1_INTEGER *BN_to_ASN1_INTEGER();
BIGNUM *ASN1_INTEGER_to_BN();
int ASN1_PRINTABLE_type();
int i2d_ASN1_bytes();
ASN1_STRING *d2i_ASN1_bytes();
ASN1_STRING *d2i_ASN1_type_bytes();
int asn1_Finish();
int ASN1_get_object();
int ASN1_check_infinite_end();
void ASN1_put_object();
int ASN1_object_size();
char *ASN1_dup();
#ifndef NO_FP_API
char *ASN1_d2i_fp();
int ASN1_i2d_fp();
#endif

char *ASN1_d2i_bio();
int ASN1_i2d_bio();
int ASN1_UTCTIME_print();
int ASN1_STRING_print();
int ASN1_parse();
int i2a_ASN1_INTEGER();
int a2i_ASN1_INTEGER();
int i2a_ASN1_OBJECT();
int i2t_ASN1_OBJECT();
int a2i_ASN1_STRING();
int i2a_ASN1_STRING();

int i2d_ASN1_HEADER();
ASN1_HEADER *d2i_ASN1_HEADER();
ASN1_HEADER *ASN1_HEADER_new();
void ASN1_HEADER_free();
void ERR_load_ASN1_strings();
ASN1_METHOD *X509_asn1_meth();
ASN1_METHOD *RSAPrivateKey_asn1_meth();
ASN1_METHOD *ASN1_IA5STRING_asn1_meth();
ASN1_METHOD *ASN1_BIT_STRING_asn1_meth();

int ASN1_UNIVERSALSTRING_to_string();

int ASN1_TYPE_set_octetstring();
int ASN1_TYPE_get_octetstring();
int ASN1_TYPE_set_int_octetstring();
int ASN1_TYPE_get_int_octetstring();

#endif

/* BEGIN ERROR CODES */
/* Error codes for the ASN1 functions. */

/* Function codes. */
#define ASN1_F_A2D_ASN1_OBJECT				 100
#define ASN1_F_A2I_ASN1_INTEGER				 101
#define ASN1_F_A2I_ASN1_STRING				 102
#define ASN1_F_ASN1_COLLATE_PRIMATIVE			 103
#define ASN1_F_ASN1_D2I_BIO				 104
#define ASN1_F_ASN1_D2I_FP				 105
#define ASN1_F_ASN1_DUP					 106
#define ASN1_F_ASN1_GET_OBJECT				 107
#define ASN1_F_ASN1_HEADER_NEW				 108
#define ASN1_F_ASN1_I2D_BIO				 109
#define ASN1_F_ASN1_I2D_FP				 110
#define ASN1_F_ASN1_INTEGER_SET				 111
#define ASN1_F_ASN1_INTEGER_TO_BN			 112
#define ASN1_F_ASN1_OBJECT_NEW				 113
#define ASN1_F_ASN1_SIGN				 114
#define ASN1_F_ASN1_STRING_NEW				 115
#define ASN1_F_ASN1_STRING_TYPE_NEW			 116
#define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING		 117
#define ASN1_F_ASN1_TYPE_GET_OCTETSTRING		 118
#define ASN1_F_ASN1_TYPE_NEW				 119
#define ASN1_F_ASN1_UTCTIME_NEW				 120
#define ASN1_F_ASN1_VERIFY				 121
#define ASN1_F_BN_TO_ASN1_INTEGER			 122
#define ASN1_F_D2I_ASN1_BIT_STRING			 123
#define ASN1_F_D2I_ASN1_BMPSTRING			 124
#define ASN1_F_D2I_ASN1_BOOLEAN				 125
#define ASN1_F_D2I_ASN1_BYTES				 126
#define ASN1_F_D2I_ASN1_HEADER				 127
#define ASN1_F_D2I_ASN1_INTEGER				 128
#define ASN1_F_D2I_ASN1_OBJECT				 129
#define ASN1_F_D2I_ASN1_OCTET_STRING			 130
#define ASN1_F_D2I_ASN1_PRINT_TYPE			 131
#define ASN1_F_D2I_ASN1_SET				 132
#define ASN1_F_D2I_ASN1_TYPE				 133
#define ASN1_F_D2I_ASN1_TYPE_BYTES			 134
#define ASN1_F_D2I_ASN1_UTCTIME				 135
#define ASN1_F_D2I_DHPARAMS				 136
#define ASN1_F_D2I_DSAPARAMS				 137
#define ASN1_F_D2I_DSAPRIVATEKEY			 138
#define ASN1_F_D2I_DSAPUBLICKEY				 139
#define ASN1_F_D2I_NETSCAPE_PKEY			 140
#define ASN1_F_D2I_NETSCAPE_RSA				 141
#define ASN1_F_D2I_NETSCAPE_RSA_2			 142
#define ASN1_F_D2I_NETSCAPE_SPKAC			 143
#define ASN1_F_D2I_NETSCAPE_SPKI			 144
#define ASN1_F_D2I_PKCS7				 145
#define ASN1_F_D2I_PKCS7_DIGEST				 146
#define ASN1_F_D2I_PKCS7_ENCRYPT			 147
#define ASN1_F_D2I_PKCS7_ENC_CONTENT			 148
#define ASN1_F_D2I_PKCS7_ENVELOPE			 149
#define ASN1_F_D2I_PKCS7_ISSUER_AND_SERIAL		 150
#define ASN1_F_D2I_PKCS7_RECIP_INFO			 151
#define ASN1_F_D2I_PKCS7_SIGNED				 152
#define ASN1_F_D2I_PKCS7_SIGNER_INFO			 153
#define ASN1_F_D2I_PKCS7_SIGN_ENVELOPE			 154
#define ASN1_F_D2I_PRIVATEKEY				 155
#define ASN1_F_D2I_PUBLICKEY				 156
#define ASN1_F_D2I_RSAPRIVATEKEY			 157
#define ASN1_F_D2I_RSAPUBLICKEY				 158
#define ASN1_F_D2I_X509					 159
#define ASN1_F_D2I_X509_ALGOR				 160
#define ASN1_F_D2I_X509_ATTRIBUTE			 161
#define ASN1_F_D2I_X509_CINF				 162
#define ASN1_F_D2I_X509_CRL				 163
#define ASN1_F_D2I_X509_CRL_INFO			 164
#define ASN1_F_D2I_X509_EXTENSION			 165
#define ASN1_F_D2I_X509_KEY				 166
#define ASN1_F_D2I_X509_NAME				 167
#define ASN1_F_D2I_X509_NAME_ENTRY			 168
#define ASN1_F_D2I_X509_PKEY				 169
#define ASN1_F_D2I_X509_PUBKEY				 170
#define ASN1_F_D2I_X509_REQ				 171
#define ASN1_F_D2I_X509_REQ_INFO			 172
#define ASN1_F_D2I_X509_REVOKED				 173
#define ASN1_F_D2I_X509_SIG				 174
#define ASN1_F_D2I_X509_VAL				 175
#define ASN1_F_I2D_ASN1_HEADER				 176
#define ASN1_F_I2D_DHPARAMS				 177
#define ASN1_F_I2D_DSAPARAMS				 178
#define ASN1_F_I2D_DSAPRIVATEKEY			 179
#define ASN1_F_I2D_DSAPUBLICKEY				 180
#define ASN1_F_I2D_NETSCAPE_RSA				 181
#define ASN1_F_I2D_PKCS7				 182
#define ASN1_F_I2D_PRIVATEKEY				 183
#define ASN1_F_I2D_PUBLICKEY				 184
#define ASN1_F_I2D_RSAPRIVATEKEY			 185
#define ASN1_F_I2D_RSAPUBLICKEY				 186
#define ASN1_F_I2D_X509_ATTRIBUTE			 187
#define ASN1_F_I2T_ASN1_OBJECT				 188
#define ASN1_F_NETSCAPE_PKEY_NEW			 189
#define ASN1_F_NETSCAPE_SPKAC_NEW			 190
#define ASN1_F_NETSCAPE_SPKI_NEW			 191
#define ASN1_F_PKCS7_DIGEST_NEW				 192
#define ASN1_F_PKCS7_ENCRYPT_NEW			 193
#define ASN1_F_PKCS7_ENC_CONTENT_NEW			 194
#define ASN1_F_PKCS7_ENVELOPE_NEW			 195
#define ASN1_F_PKCS7_ISSUER_AND_SERIAL_NEW		 196
#define ASN1_F_PKCS7_NEW				 197
#define ASN1_F_PKCS7_RECIP_INFO_NEW			 198
#define ASN1_F_PKCS7_SIGNED_NEW				 199
#define ASN1_F_PKCS7_SIGNER_INFO_NEW			 200
#define ASN1_F_PKCS7_SIGN_ENVELOPE_NEW			 201
#define ASN1_F_X509_ALGOR_NEW				 202
#define ASN1_F_X509_ATTRIBUTE_NEW			 203
#define ASN1_F_X509_CINF_NEW				 204
#define ASN1_F_X509_CRL_INFO_NEW			 205
#define ASN1_F_X509_CRL_NEW				 206
#define ASN1_F_X509_DHPARAMS_NEW			 207
#define ASN1_F_X509_EXTENSION_NEW			 208
#define ASN1_F_X509_INFO_NEW				 209
#define ASN1_F_X509_KEY_NEW				 210
#define ASN1_F_X509_NAME_ENTRY_NEW			 211
#define ASN1_F_X509_NAME_NEW				 212
#define ASN1_F_X509_NEW					 213
#define ASN1_F_X509_PKEY_NEW				 214
#define ASN1_F_X509_PUBKEY_NEW				 215
#define ASN1_F_X509_REQ_INFO_NEW			 216
#define ASN1_F_X509_REQ_NEW				 217
#define ASN1_F_X509_REVOKED_NEW				 218
#define ASN1_F_X509_SIG_NEW				 219
#define ASN1_F_X509_VAL_FREE				 220
#define ASN1_F_X509_VAL_NEW				 221

/* Reason codes. */
#define ASN1_R_BAD_CLASS				 100
#define ASN1_R_BAD_GET_OBJECT				 101
#define ASN1_R_BAD_OBJECT_HEADER			 102
#define ASN1_R_BAD_PASSWORD_READ			 103
#define ASN1_R_BAD_PKCS7_CONTENT			 104
#define ASN1_R_BAD_PKCS7_TYPE				 105
#define ASN1_R_BAD_TAG					 106
#define ASN1_R_BAD_TYPE					 107
#define ASN1_R_BN_LIB					 108
#define ASN1_R_BOOLEAN_IS_WRONG_LENGTH			 109
#define ASN1_R_BUFFER_TOO_SMALL				 110
#define ASN1_R_DATA_IS_WRONG				 111
#define ASN1_R_DECODING_ERROR				 112
#define ASN1_R_ERROR_STACK				 113
#define ASN1_R_EXPECTING_AN_INTEGER			 114
#define ASN1_R_EXPECTING_AN_OBJECT			 115
#define ASN1_R_EXPECTING_AN_OCTET_STRING		 116
#define ASN1_R_EXPECTING_A_BIT_STRING			 117
#define ASN1_R_EXPECTING_A_BOOLEAN			 118
#define ASN1_R_EXPECTING_A_SEQUENCE			 119
#define ASN1_R_EXPECTING_A_UTCTIME			 120
#define ASN1_R_FIRST_NUM_TOO_LARGE			 121
#define ASN1_R_HEADER_TOO_LONG				 122
#define ASN1_R_INVALID_DIGIT				 123
#define ASN1_R_INVALID_SEPARATOR			 124
#define ASN1_R_INVALID_TIME_FORMAT			 125
#define ASN1_R_IV_TOO_LARGE				 126
#define ASN1_R_LENGTH_ERROR				 127
#define ASN1_R_LENGTH_MISMATCH				 128
#define ASN1_R_MISSING_EOS				 129
#define ASN1_R_MISSING_SECOND_NUMBER			 130
#define ASN1_R_NON_HEX_CHARACTERS			 131
#define ASN1_R_NOT_ENOUGH_DATA				 132
#define ASN1_R_ODD_NUMBER_OF_CHARS			 133
#define ASN1_R_PARSING					 134
#define ASN1_R_PRIVATE_KEY_HEADER_MISSING		 135
#define ASN1_R_SECOND_NUMBER_TOO_LARGE			 136
#define ASN1_R_SHORT_LINE				 137
#define ASN1_R_STRING_TOO_SHORT				 138
#define ASN1_R_TAG_VALUE_TOO_HIGH			 139
#define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 140
#define ASN1_R_TOO_LONG					 141
#define ASN1_R_UNABLE_TO_DECODE_RSA_KEY			 142
#define ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY		 143
#define ASN1_R_UNKNOWN_ATTRIBUTE_TYPE			 144
#define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM		 145
#define ASN1_R_UNKNOWN_OBJECT_TYPE			 146
#define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE			 147
#define ASN1_R_UNSUPPORTED_CIPHER			 148
#define ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM		 149
#define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE		 150
#define ASN1_R_UTCTIME_TOO_LONG				 151
#define ASN1_R_WRONG_PRINTABLE_TYPE			 152
#define ASN1_R_WRONG_TAG				 153
#define ASN1_R_WRONG_TYPE				 154
 
#ifdef  __cplusplus
}
#endif
#endif

