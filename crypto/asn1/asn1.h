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

#include <time.h>
#ifndef NO_BIO
#include <openssl/bio.h>
#endif
#include <openssl/bn.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#include <openssl/symhacks.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define V_ASN1_UNIVERSAL		0x00
#define	V_ASN1_APPLICATION		0x40
#define V_ASN1_CONTEXT_SPECIFIC		0x80
#define V_ASN1_PRIVATE			0xc0

#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMITIVE_TAG		0x1f
#define V_ASN1_PRIMATIVE_TAG		0x1f

#define V_ASN1_APP_CHOOSE		-2	/* let the recipient choose */
#define V_ASN1_OTHER			-3	/* used in ASN1_TYPE */

#define V_ASN1_NEG			0x100	/* negative flag */

#define V_ASN1_UNDEF			-1
#define V_ASN1_EOC			0
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_OBJECT_DESCRIPTOR	7
#define V_ASN1_EXTERNAL			8
#define V_ASN1_REAL			9
#define V_ASN1_ENUMERATED		10
#define V_ASN1_NEG_ENUMERATED		(10 | V_ASN1_NEG)
#define V_ASN1_UTF8STRING		12
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
#define B_ASN1_TELETEXSTRING	0x0008
#define B_ASN1_VIDEOTEXSTRING	0x0008
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_GRAPHICSTRING	0x0020
#define B_ASN1_ISO64STRING	0x0040
#define B_ASN1_VISIBLESTRING	0x0040
#define B_ASN1_GENERALSTRING	0x0080
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_OCTET_STRING	0x0200
#define B_ASN1_BIT_STRING	0x0400
#define B_ASN1_BMPSTRING	0x0800
#define B_ASN1_UNKNOWN		0x1000
#define B_ASN1_UTF8STRING	0x2000

/* For use with ASN1_mbstring_copy() */
#define MBSTRING_FLAG		0x1000
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|3)
#define MBSTRING_UTF8		(MBSTRING_FLAG|4)

struct X509_algor_st;

#define DECLARE_ASN1_SET_OF(type) /* filled in by mkstack.pl */
#define IMPLEMENT_ASN1_SET_OF(type) /* nothing, no longer needed */

typedef struct asn1_ctx_st
	{
	unsigned char *p;/* work char pointer */
	int eos;	/* end of sequence read for indefinite encoding */
	int error;	/* error code to use when returning an error */
	int inf;	/* constructed if 0x20, indefinite is 0x21 */
	int tag;	/* tag from last 'get object' */
	int xclass;	/* class from last 'get object' */
	long slen;	/* length of last 'get object' */
	unsigned char *max; /* largest value of p allowed */
	unsigned char *q;/* temporary variable */
	unsigned char **pp;/* variable */
	int line;	/* used in error processing */
	} ASN1_CTX;

/* These are used internally in the ASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed */
#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_CRITICAL	 0x02	/* critical x509v3 object id */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
typedef struct asn1_object_st
	{
	const char *sn,*ln;
	int nid;
	int length;
	unsigned char *data;
	int flags;	/* Should we free this one */
	} ASN1_OBJECT;

#define ASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */
/* This is the base type that holds just about everything :-) */
typedef struct asn1_string_st
	{
	int length;
	int type;
	unsigned char *data;
	/* The value of the following field depends on the type being
	 * held.  It is mostly being used for BIT_STRING so if the
	 * input data has a non-zero 'unused bits' value, it will be
	 * handled correctly */
	long flags;
	} ASN1_STRING;

#define STABLE_FLAGS_MALLOC	0x01
#define STABLE_NO_MASK		0x02
#define DIRSTRING_TYPE	\
 (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)
#define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)

typedef struct asn1_string_table_st {
	int nid;
	long minsize;
	long maxsize;
	unsigned long mask;
	unsigned long flags;
} ASN1_STRING_TABLE;

DECLARE_STACK_OF(ASN1_STRING_TABLE)

/* size limits: this stuff is taken straight from RFC2459 */

#define ub_name				32768
#define ub_common_name			64
#define ub_locality_name		128
#define ub_state_name			128
#define ub_organization_name		64
#define ub_organization_unit_name	64
#define ub_title			64
#define ub_email_address		128

#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER		ASN1_STRING
#define ASN1_ENUMERATED		ASN1_STRING
#define ASN1_BIT_STRING		ASN1_STRING
#define ASN1_OCTET_STRING	ASN1_STRING
#define ASN1_PRINTABLESTRING	ASN1_STRING
#define ASN1_T61STRING		ASN1_STRING
#define ASN1_IA5STRING		ASN1_STRING
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_TIME		ASN1_STRING
#define ASN1_GENERALSTRING	ASN1_STRING
#define ASN1_UNIVERSALSTRING	ASN1_STRING
#define ASN1_BMPSTRING		ASN1_STRING
#define ASN1_VISIBLESTRING	ASN1_STRING
#define ASN1_UTF8STRING		ASN1_STRING
#define ASN1_BOOLEAN		int
#else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef int ASN1_BOOLEAN;
#endif

typedef int ASN1_NULL;

/* Parameters used by ASN1_STRING_print_ex() */

/* These determine which characters to escape:
 * RFC2253 special characters, control characters and
 * MSB set characters
 */

#define ASN1_STRFLGS_ESC_2253		1
#define ASN1_STRFLGS_ESC_CTRL		2
#define ASN1_STRFLGS_ESC_MSB		4


/* This flag determines how we do escaping: normally
 * RC2253 backslash only, set this to use backslash and
 * quote.
 */

#define ASN1_STRFLGS_ESC_QUOTE		8


/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
#define CHARTYPE_PRINTABLESTRING	0x10
/* Character needs escaping if it is the first character */
#define CHARTYPE_FIRST_ESC_2253		0x20
/* Character needs escaping if it is the last character */
#define CHARTYPE_LAST_ESC_2253		0x40

/* NB the internal flags are safely reused below by flags
 * handled at the top level.
 */

/* If this is set we convert all character strings
 * to UTF8 first 
 */

#define ASN1_STRFLGS_UTF8_CONVERT	0x10

/* If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */

#define ASN1_STRFLGS_IGNORE_TYPE	0x20

/* If this is set we include the string type in the output */
#define ASN1_STRFLGS_SHOW_TYPE		0x40

/* This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */

#define ASN1_STRFLGS_DUMP_ALL		0x80
#define ASN1_STRFLGS_DUMP_UNKNOWN	0x100

/* These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #XXXXX notation.
 */

#define ASN1_STRFLGS_DUMP_DER		0x200

/* All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */

#define ASN1_STRFLGS_RFC2253	(ASN1_STRFLGS_ESC_2253 | \
				ASN1_STRFLGS_ESC_CTRL | \
				ASN1_STRFLGS_ESC_MSB | \
				ASN1_STRFLGS_UTF8_CONVERT | \
				ASN1_STRFLGS_DUMP_UNKNOWN | \
				ASN1_STRFLGS_DUMP_DER)

DECLARE_STACK_OF(ASN1_INTEGER)
DECLARE_ASN1_SET_OF(ASN1_INTEGER)

typedef struct asn1_type_st
	{
	int type;
	union	{
		char *ptr;
		ASN1_BOOLEAN		boolean;
		ASN1_STRING *		asn1_string;
		ASN1_OBJECT *		object;
		ASN1_INTEGER *		integer;
		ASN1_ENUMERATED *	enumerated;
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
		ASN1_VISIBLESTRING *	visiblestring;
		ASN1_UTF8STRING *	utf8string;
		/* set and sequence are left complete and still
		 * contain the set or sequence bytes */
		ASN1_STRING *		set;
		ASN1_STRING *		sequence;
		} value;
	} ASN1_TYPE;

DECLARE_STACK_OF(ASN1_TYPE)
DECLARE_ASN1_SET_OF(ASN1_TYPE)

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

/* This is used to contain a list of bit names */
typedef struct BIT_STRING_BITNAME_st {
	int bitnum;
	const char *lname;
	const char *sname;
} BIT_STRING_BITNAME;


#define M_ASN1_STRING_length(x)	((x)->length)
#define M_ASN1_STRING_length_set(x, n)	((x)->length = (n))
#define M_ASN1_STRING_type(x)	((x)->type)
#define M_ASN1_STRING_data(x)	((x)->data)

/* Macros for string operations */
#define M_ASN1_BIT_STRING_new()	(ASN1_BIT_STRING *)\
		ASN1_STRING_type_new(V_ASN1_BIT_STRING)
#define M_ASN1_BIT_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_BIT_STRING_dup(a) (ASN1_BIT_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_BIT_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define M_ASN1_BIT_STRING_set(a,b,c) ASN1_STRING_set((ASN1_STRING *)a,b,c)

#define M_ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)
#define M_ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_INTEGER_dup(a) (ASN1_INTEGER *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_INTEGER_cmp(a,b)	ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)

#define M_ASN1_ENUMERATED_new()	(ASN1_ENUMERATED *)\
		ASN1_STRING_type_new(V_ASN1_ENUMERATED)
#define M_ASN1_ENUMERATED_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_ENUMERATED_dup(a) (ASN1_ENUMERATED *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_ENUMERATED_cmp(a,b)	ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)

#define M_ASN1_OCTET_STRING_new()	(ASN1_OCTET_STRING *)\
		ASN1_STRING_type_new(V_ASN1_OCTET_STRING)
#define M_ASN1_OCTET_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_OCTET_STRING_dup(a) (ASN1_OCTET_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_OCTET_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define M_ASN1_OCTET_STRING_set(a,b,c)	ASN1_STRING_set((ASN1_STRING *)a,b,c)
#define M_ASN1_OCTET_STRING_print(a,b)	ASN1_STRING_print(a,(ASN1_STRING *)b)
#define M_i2d_ASN1_OCTET_STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_OCTET_STRING,\
		V_ASN1_UNIVERSAL)

#define M_ASN1_PRINTABLE_new()	ASN1_STRING_type_new(V_ASN1_T61STRING)
#define M_ASN1_PRINTABLE_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
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
			B_ASN1_UTF8STRING|\
			B_ASN1_UNKNOWN)

#define M_DIRECTORYSTRING_new() ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
#define M_DIRECTORYSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_DIRECTORYSTRING(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
						pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_DIRECTORYSTRING(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_PRINTABLESTRING| \
			B_ASN1_TELETEXSTRING|\
			B_ASN1_BMPSTRING|\
			B_ASN1_UNIVERSALSTRING|\
			B_ASN1_UTF8STRING)

#define M_DISPLAYTEXT_new() ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define M_DISPLAYTEXT_free(a) ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_DISPLAYTEXT(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
						pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_DISPLAYTEXT(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_VISIBLESTRING| \
			B_ASN1_BMPSTRING|\
			B_ASN1_UTF8STRING)

#define M_ASN1_PRINTABLESTRING_new() (ASN1_PRINTABLESTRING *)\
		ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
#define M_ASN1_PRINTABLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_PRINTABLESTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_PRINTABLESTRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_PRINTABLESTRING(a,pp,l) \
		(ASN1_PRINTABLESTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_PRINTABLESTRING)

#define M_ASN1_T61STRING_new()	(ASN1_T61STRING *)\
		ASN1_STRING_type_new(V_ASN1_T61STRING)
#define M_ASN1_T61STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_T61STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_T61STRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_T61STRING(a,pp,l) \
		(ASN1_T61STRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_T61STRING)

#define M_ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)
#define M_ASN1_IA5STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_IA5STRING_dup(a)	\
			(ASN1_IA5STRING *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_i2d_ASN1_IA5STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_IA5STRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_IA5STRING(a,pp,l) \
		(ASN1_IA5STRING *)d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l,\
			B_ASN1_IA5STRING)

#define M_ASN1_UTCTIME_new()	(ASN1_UTCTIME *)\
		ASN1_STRING_type_new(V_ASN1_UTCTIME)
#define M_ASN1_UTCTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_UTCTIME_dup(a) (ASN1_UTCTIME *)ASN1_STRING_dup((ASN1_STRING *)a)

#define M_ASN1_GENERALIZEDTIME_new()	(ASN1_GENERALIZEDTIME *)\
		ASN1_STRING_type_new(V_ASN1_GENERALIZEDTIME)
#define M_ASN1_GENERALIZEDTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_GENERALIZEDTIME_dup(a) (ASN1_GENERALIZEDTIME *)ASN1_STRING_dup(\
	(ASN1_STRING *)a)

#define M_ASN1_TIME_new()	(ASN1_TIME *)\
		ASN1_STRING_type_new(V_ASN1_UTCTIME)
#define M_ASN1_TIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_TIME_dup(a) (ASN1_TIME *)ASN1_STRING_dup((ASN1_STRING *)a)

#define M_ASN1_GENERALSTRING_new()	(ASN1_GENERALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_GENERALSTRING)
#define M_ASN1_GENERALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_GENERALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_GENERALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_GENERALSTRING(a,pp,l) \
		(ASN1_GENERALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_GENERALSTRING)

#define M_ASN1_UNIVERSALSTRING_new()	(ASN1_UNIVERSALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_UNIVERSALSTRING)
#define M_ASN1_UNIVERSALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_UNIVERSALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_UNIVERSALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_UNIVERSALSTRING(a,pp,l) \
		(ASN1_UNIVERSALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_UNIVERSALSTRING)

#define M_ASN1_BMPSTRING_new()	(ASN1_BMPSTRING *)\
		ASN1_STRING_type_new(V_ASN1_BMPSTRING)
#define M_ASN1_BMPSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_BMPSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_BMPSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_BMPSTRING(a,pp,l) \
		(ASN1_BMPSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_BMPSTRING)

#define M_ASN1_VISIBLESTRING_new()	(ASN1_VISIBLESTRING *)\
		ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define M_ASN1_VISIBLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_VISIBLESTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_VISIBLESTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_VISIBLESTRING(a,pp,l) \
		(ASN1_VISIBLESTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_VISIBLESTRING)

#define M_ASN1_UTF8STRING_new()	(ASN1_UTF8STRING *)\
		ASN1_STRING_type_new(V_ASN1_UTF8STRING)
#define M_ASN1_UTF8STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_UTF8STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_UTF8STRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_UTF8STRING(a,pp,l) \
		(ASN1_UTF8STRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_UTF8STRING)

  /* for the is_set parameter to i2d_ASN1_SET */
#define IS_SEQUENCE	0
#define IS_SET		1

ASN1_TYPE *	ASN1_TYPE_new(void );
void		ASN1_TYPE_free(ASN1_TYPE *a);
int		i2d_ASN1_TYPE(ASN1_TYPE *a,unsigned char **pp);
ASN1_TYPE *	d2i_ASN1_TYPE(ASN1_TYPE **a,unsigned char **pp,long length);
int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);

ASN1_OBJECT *	ASN1_OBJECT_new(void );
void		ASN1_OBJECT_free(ASN1_OBJECT *a);
int		i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a,unsigned char **pp,
			long length);
ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,unsigned char **pp,
			long length);

DECLARE_STACK_OF(ASN1_OBJECT)
DECLARE_ASN1_SET_OF(ASN1_OBJECT)

ASN1_STRING *	ASN1_STRING_new(void);
void		ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_dup(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_type_new(int type );
int 		ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b);
  /* Since this is used to store all sorts of things, via macros, for now, make
     its data void * */
int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
int ASN1_STRING_length(ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(ASN1_STRING *x);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);

ASN1_BIT_STRING *	ASN1_BIT_STRING_new(void);
void		ASN1_BIT_STRING_free(ASN1_BIT_STRING *a);
int		i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
int		i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,unsigned char **pp,
			long length);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,unsigned char **pp,
			long length);
int		ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d,
			int length );
int		ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int		ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);

#ifndef NO_BIO
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
				BIT_STRING_BITNAME *tbl, int indent);
#endif
int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
				BIT_STRING_BITNAME *tbl);

int		i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int 		d2i_ASN1_BOOLEAN(int *a,unsigned char **pp,long length);

ASN1_INTEGER *	ASN1_INTEGER_new(void);
void		ASN1_INTEGER_free(ASN1_INTEGER *a);
int		i2d_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
int		i2c_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a,unsigned char **pp,
			long length);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,unsigned char **pp,
			long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,unsigned char **pp,
			long length);
ASN1_INTEGER *	ASN1_INTEGER_dup(ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(ASN1_INTEGER *x, ASN1_INTEGER *y);

ASN1_ENUMERATED *	ASN1_ENUMERATED_new(void);
void		ASN1_ENUMERATED_free(ASN1_ENUMERATED *a);
int		i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a,unsigned char **pp);
ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a,unsigned char **pp,
			long length);

int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, char *str); 
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
#if 0
time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s);
#endif

int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, char *str); 

ASN1_OCTET_STRING *	ASN1_OCTET_STRING_new(void);
void		ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a);
int		i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a,unsigned char **pp);
ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a,
			unsigned char **pp,long length);
ASN1_OCTET_STRING *	ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *a);
int 	ASN1_OCTET_STRING_cmp(ASN1_OCTET_STRING *a, ASN1_OCTET_STRING *b);
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, unsigned char *data, int len);

ASN1_VISIBLESTRING *	ASN1_VISIBLESTRING_new(void);
void		ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a);
int	i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a,unsigned char **pp);
ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a,
			unsigned char **pp,long length);

ASN1_UTF8STRING *	ASN1_UTF8STRING_new(void);
void		ASN1_UTF8STRING_free(ASN1_UTF8STRING *a);
int		i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a,unsigned char **pp);
ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a,
			unsigned char **pp,long length);

ASN1_NULL *	ASN1_NULL_new(void);
void		ASN1_NULL_free(ASN1_NULL *a);
int		i2d_ASN1_NULL(ASN1_NULL *a,unsigned char **pp);
ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, unsigned char **pp,long length);

ASN1_BMPSTRING *	ASN1_BMPSTRING_new(void);
void		ASN1_BMPSTRING_free(ASN1_BMPSTRING *a);
int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **pp);
ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, unsigned char **pp,
	long length);


int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

int i2d_ASN1_PRINTABLE(ASN1_STRING *a,unsigned char **pp);
ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a,
	unsigned char **pp, long l);

ASN1_PRINTABLESTRING *	ASN1_PRINTABLESTRING_new(void);
void		ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a);
ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a,
	unsigned char **pp, long l);
int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, unsigned char **pp);

ASN1_STRING *	DIRECTORYSTRING_new(void);
void		DIRECTORYSTRING_free(ASN1_STRING *a);
int	i2d_DIRECTORYSTRING(ASN1_STRING *a,unsigned char **pp);
ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, unsigned char **pp,
								 long length);

ASN1_STRING *	DISPLAYTEXT_new(void);
void		DISPLAYTEXT_free(ASN1_STRING *a);
int	i2d_DISPLAYTEXT(ASN1_STRING *a,unsigned char **pp);
ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, unsigned char **pp, long length);

ASN1_T61STRING *	ASN1_T61STRING_new(void);
void		ASN1_T61STRING_free(ASN1_IA5STRING *a);
ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a,
	unsigned char **pp, long l);

ASN1_IA5STRING *	ASN1_IA5STRING_new(void);
void		ASN1_IA5STRING_free(ASN1_IA5STRING *a);
int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a,unsigned char **pp);
ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a,
	unsigned char **pp, long l);

ASN1_UTCTIME *	ASN1_UTCTIME_new(void);
void		ASN1_UTCTIME_free(ASN1_UTCTIME *a);
int		i2d_ASN1_UTCTIME(ASN1_UTCTIME *a,unsigned char **pp);
ASN1_UTCTIME *	d2i_ASN1_UTCTIME(ASN1_UTCTIME **a,unsigned char **pp,
			long length);

ASN1_GENERALIZEDTIME *	ASN1_GENERALIZEDTIME_new(void);
void		ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a);
int		i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a,unsigned char **pp);
ASN1_GENERALIZEDTIME *	d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a,unsigned char **pp,
			long length);

ASN1_TIME *	ASN1_TIME_new(void);
void		ASN1_TIME_free(ASN1_TIME *a);
int		i2d_ASN1_TIME(ASN1_TIME *a,unsigned char **pp);
ASN1_TIME *	d2i_ASN1_TIME(ASN1_TIME **a,unsigned char **pp, long length);
ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);

int		i2d_ASN1_SET(STACK *a, unsigned char **pp,
			int (*func)(), int ex_tag, int ex_class, int is_set);
STACK *		d2i_ASN1_SET(STACK **a, unsigned char **pp, long length,
			char *(*func)(), void (*free_func)(void *),
			int ex_tag, int ex_class);

#ifndef NO_BIO
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);
#endif
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
	char *sn, char *ln);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);

int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);

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
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags);
#endif

int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);

#ifndef NO_BIO
char *ASN1_d2i_bio(char *(*xnew)(),char *(*d2i)(),BIO *bp,unsigned char **x);
int ASN1_i2d_bio(int (*i2d)(),BIO *out,unsigned char *x);
int ASN1_UTCTIME_print(BIO *fp,ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp,ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp,ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp,ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_parse(BIO *bp,unsigned char *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,unsigned char *pp,long len,int indent,int dump);
#endif
const char *ASN1_tag2str(int tag);

/* Used to load and write netscape format cert/key */
int i2d_ASN1_HEADER(ASN1_HEADER *a,unsigned char **pp);
ASN1_HEADER *d2i_ASN1_HEADER(ASN1_HEADER **a,unsigned char **pp, long length);
ASN1_HEADER *ASN1_HEADER_new(void );
void ASN1_HEADER_free(ASN1_HEADER *a);

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

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

STACK *ASN1_seq_unpack(unsigned char *buf, int len, char *(*d2i)(),
						 void (*free_func)(void *) ); 
unsigned char *ASN1_seq_pack(STACK *safes, int (*i2d)(), unsigned char **buf,
			     int *len );
void *ASN1_unpack_string(ASN1_STRING *oct, char *(*d2i)());
ASN1_STRING *ASN1_pack_string(void *obj, int (*i2d)(), ASN1_OCTET_STRING **oct);

void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask, 
					long minsize, long maxsize);

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, 
		const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ASN1_strings(void);

/* Error codes for the ASN1 functions. */

/* Function codes. */
#define ASN1_F_A2D_ASN1_OBJECT				 100
#define ASN1_F_A2I_ASN1_ENUMERATED			 236
#define ASN1_F_A2I_ASN1_INTEGER				 101
#define ASN1_F_A2I_ASN1_STRING				 102
#define ASN1_F_ACCESS_DESCRIPTION_NEW			 291
#define ASN1_F_ASN1_COLLATE_PRIMITIVE			 103
#define ASN1_F_ASN1_D2I_BIO				 104
#define ASN1_F_ASN1_D2I_FP				 105
#define ASN1_F_ASN1_DUP					 106
#define ASN1_F_ASN1_ENUMERATED_SET			 232
#define ASN1_F_ASN1_ENUMERATED_TO_BN			 233
#define ASN1_F_ASN1_GENERALIZEDTIME_NEW			 222
#define ASN1_F_ASN1_GET_OBJECT				 107
#define ASN1_F_ASN1_HEADER_NEW				 108
#define ASN1_F_ASN1_I2D_BIO				 109
#define ASN1_F_ASN1_I2D_FP				 110
#define ASN1_F_ASN1_INTEGER_SET				 111
#define ASN1_F_ASN1_INTEGER_TO_BN			 112
#define ASN1_F_ASN1_MBSTRING_COPY			 282
#define ASN1_F_ASN1_OBJECT_NEW				 113
#define ASN1_F_ASN1_PACK_STRING				 245
#define ASN1_F_ASN1_PBE_SET				 253
#define ASN1_F_ASN1_SEQ_PACK				 246
#define ASN1_F_ASN1_SEQ_UNPACK				 247
#define ASN1_F_ASN1_SIGN				 114
#define ASN1_F_ASN1_STRING_NEW				 115
#define ASN1_F_ASN1_STRING_TABLE_ADD			 283
#define ASN1_F_ASN1_STRING_TYPE_NEW			 116
#define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING		 117
#define ASN1_F_ASN1_TYPE_GET_OCTETSTRING		 118
#define ASN1_F_ASN1_TYPE_NEW				 119
#define ASN1_F_ASN1_UNPACK_STRING			 248
#define ASN1_F_ASN1_UTCTIME_NEW				 120
#define ASN1_F_ASN1_VERIFY				 121
#define ASN1_F_AUTHORITY_KEYID_NEW			 237
#define ASN1_F_BASIC_CONSTRAINTS_NEW			 226
#define ASN1_F_BN_TO_ASN1_ENUMERATED			 234
#define ASN1_F_BN_TO_ASN1_INTEGER			 122
#define ASN1_F_D2I_ACCESS_DESCRIPTION			 284
#define ASN1_F_D2I_ASN1_BIT_STRING			 123
#define ASN1_F_D2I_ASN1_BMPSTRING			 124
#define ASN1_F_D2I_ASN1_BOOLEAN				 125
#define ASN1_F_D2I_ASN1_BYTES				 126
#define ASN1_F_D2I_ASN1_ENUMERATED			 235
#define ASN1_F_D2I_ASN1_GENERALIZEDTIME			 223
#define ASN1_F_D2I_ASN1_HEADER				 127
#define ASN1_F_D2I_ASN1_INTEGER				 128
#define ASN1_F_D2I_ASN1_NULL				 292
#define ASN1_F_D2I_ASN1_OBJECT				 129
#define ASN1_F_D2I_ASN1_OCTET_STRING			 130
#define ASN1_F_D2I_ASN1_PRINT_TYPE			 131
#define ASN1_F_D2I_ASN1_SET				 132
#define ASN1_F_D2I_ASN1_TIME				 224
#define ASN1_F_D2I_ASN1_TYPE				 133
#define ASN1_F_D2I_ASN1_TYPE_BYTES			 134
#define ASN1_F_D2I_ASN1_UINTEGER			 280
#define ASN1_F_D2I_ASN1_UTCTIME				 135
#define ASN1_F_D2I_ASN1_UTF8STRING			 266
#define ASN1_F_D2I_ASN1_VISIBLESTRING			 267
#define ASN1_F_D2I_AUTHORITY_KEYID			 238
#define ASN1_F_D2I_BASIC_CONSTRAINTS			 227
#define ASN1_F_D2I_DHPARAMS				 136
#define ASN1_F_D2I_DIST_POINT				 276
#define ASN1_F_D2I_DIST_POINT_NAME			 277
#define ASN1_F_D2I_DSAPARAMS				 137
#define ASN1_F_D2I_DSAPRIVATEKEY			 138
#define ASN1_F_D2I_DSAPUBLICKEY				 139
#define ASN1_F_D2I_GENERAL_NAME				 230
#define ASN1_F_D2I_NETSCAPE_CERT_SEQUENCE		 228
#define ASN1_F_D2I_NETSCAPE_PKEY			 140
#define ASN1_F_D2I_NETSCAPE_RSA				 141
#define ASN1_F_D2I_NETSCAPE_RSA_2			 142
#define ASN1_F_D2I_NETSCAPE_SPKAC			 143
#define ASN1_F_D2I_NETSCAPE_SPKI			 144
#define ASN1_F_D2I_NOTICEREF				 268
#define ASN1_F_D2I_OTHERNAME				 287
#define ASN1_F_D2I_PBE2PARAM				 262
#define ASN1_F_D2I_PBEPARAM				 249
#define ASN1_F_D2I_PBKDF2PARAM				 263
#define ASN1_F_D2I_PKCS12				 254
#define ASN1_F_D2I_PKCS12_BAGS				 255
#define ASN1_F_D2I_PKCS12_MAC_DATA			 256
#define ASN1_F_D2I_PKCS12_SAFEBAG			 257
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
#define ASN1_F_D2I_PKCS8_PRIV_KEY_INFO			 250
#define ASN1_F_D2I_PKEY_USAGE_PERIOD			 239
#define ASN1_F_D2I_POLICYINFO				 269
#define ASN1_F_D2I_POLICYQUALINFO			 270
#define ASN1_F_D2I_PRIVATEKEY				 155
#define ASN1_F_D2I_PUBLICKEY				 156
#define ASN1_F_D2I_RSAPRIVATEKEY			 157
#define ASN1_F_D2I_RSAPUBLICKEY				 158
#define ASN1_F_D2I_SXNET				 241
#define ASN1_F_D2I_SXNETID				 243
#define ASN1_F_D2I_USERNOTICE				 271
#define ASN1_F_D2I_X509					 159
#define ASN1_F_D2I_X509_ALGOR				 160
#define ASN1_F_D2I_X509_ATTRIBUTE			 161
#define ASN1_F_D2I_X509_CERT_AUX			 285
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
#define ASN1_F_DIST_POINT_NAME_NEW			 278
#define ASN1_F_DIST_POINT_NEW				 279
#define ASN1_F_GENERAL_NAME_NEW				 231
#define ASN1_F_I2D_ASN1_HEADER				 176
#define ASN1_F_I2D_ASN1_TIME				 225
#define ASN1_F_I2D_DHPARAMS				 177
#define ASN1_F_I2D_DSAPARAMS				 178
#define ASN1_F_I2D_DSAPRIVATEKEY			 179
#define ASN1_F_I2D_DSAPUBLICKEY				 180
#define ASN1_F_I2D_DSA_PUBKEY				 290
#define ASN1_F_I2D_NETSCAPE_RSA				 181
#define ASN1_F_I2D_PKCS7				 182
#define ASN1_F_I2D_PRIVATEKEY				 183
#define ASN1_F_I2D_PUBLICKEY				 184
#define ASN1_F_I2D_RSAPRIVATEKEY			 185
#define ASN1_F_I2D_RSAPUBLICKEY				 186
#define ASN1_F_I2D_RSA_PUBKEY				 289
#define ASN1_F_I2D_X509_ATTRIBUTE			 187
#define ASN1_F_I2T_ASN1_OBJECT				 188
#define ASN1_F_NETSCAPE_CERT_SEQUENCE_NEW		 229
#define ASN1_F_NETSCAPE_PKEY_NEW			 189
#define ASN1_F_NETSCAPE_SPKAC_NEW			 190
#define ASN1_F_NETSCAPE_SPKI_NEW			 191
#define ASN1_F_NOTICEREF_NEW				 272
#define ASN1_F_OTHERNAME_NEW				 288
#define ASN1_F_PBE2PARAM_NEW				 264
#define ASN1_F_PBEPARAM_NEW				 251
#define ASN1_F_PBKDF2PARAM_NEW				 265
#define ASN1_F_PKCS12_BAGS_NEW				 258
#define ASN1_F_PKCS12_MAC_DATA_NEW			 259
#define ASN1_F_PKCS12_NEW				 260
#define ASN1_F_PKCS12_SAFEBAG_NEW			 261
#define ASN1_F_PKCS5_PBE2_SET				 281
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
#define ASN1_F_PKCS8_PRIV_KEY_INFO_NEW			 252
#define ASN1_F_PKEY_USAGE_PERIOD_NEW			 240
#define ASN1_F_POLICYINFO_NEW				 273
#define ASN1_F_POLICYQUALINFO_NEW			 274
#define ASN1_F_SXNETID_NEW				 244
#define ASN1_F_SXNET_NEW				 242
#define ASN1_F_USERNOTICE_NEW				 275
#define ASN1_F_X509_ALGOR_NEW				 202
#define ASN1_F_X509_ATTRIBUTE_NEW			 203
#define ASN1_F_X509_CERT_AUX_NEW			 286
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
#define ASN1_R_BAD_OBJECT_HEADER			 101
#define ASN1_R_BAD_PASSWORD_READ			 102
#define ASN1_R_BAD_PKCS7_CONTENT			 103
#define ASN1_R_BAD_PKCS7_TYPE				 104
#define ASN1_R_BAD_TAG					 105
#define ASN1_R_BAD_TYPE					 106
#define ASN1_R_BN_LIB					 107
#define ASN1_R_BOOLEAN_IS_WRONG_LENGTH			 108
#define ASN1_R_BUFFER_TOO_SMALL				 109
#define ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER		 166
#define ASN1_R_DATA_IS_WRONG				 110
#define ASN1_R_DECODE_ERROR				 155
#define ASN1_R_DECODING_ERROR				 111
#define ASN1_R_ENCODE_ERROR				 156
#define ASN1_R_ERROR_PARSING_SET_ELEMENT		 112
#define ASN1_R_ERROR_SETTING_CIPHER_PARAMS		 157
#define ASN1_R_EXPECTING_AN_ENUMERATED			 154
#define ASN1_R_EXPECTING_AN_INTEGER			 113
#define ASN1_R_EXPECTING_AN_OBJECT			 114
#define ASN1_R_EXPECTING_AN_OCTET_STRING		 115
#define ASN1_R_EXPECTING_A_BIT_STRING			 116
#define ASN1_R_EXPECTING_A_BOOLEAN			 117
#define ASN1_R_EXPECTING_A_GENERALIZEDTIME		 151
#define ASN1_R_EXPECTING_A_NULL				 164
#define ASN1_R_EXPECTING_A_TIME				 152
#define ASN1_R_EXPECTING_A_UTCTIME			 118
#define ASN1_R_FIRST_NUM_TOO_LARGE			 119
#define ASN1_R_GENERALIZEDTIME_TOO_LONG			 153
#define ASN1_R_HEADER_TOO_LONG				 120
#define ASN1_R_ILLEGAL_CHARACTERS			 158
#define ASN1_R_INVALID_BMPSTRING_LENGTH			 159
#define ASN1_R_INVALID_DIGIT				 121
#define ASN1_R_INVALID_SEPARATOR			 122
#define ASN1_R_INVALID_TIME_FORMAT			 123
#define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH		 160
#define ASN1_R_INVALID_UTF8STRING			 161
#define ASN1_R_IV_TOO_LARGE				 124
#define ASN1_R_LENGTH_ERROR				 125
#define ASN1_R_MISSING_SECOND_NUMBER			 126
#define ASN1_R_NON_HEX_CHARACTERS			 127
#define ASN1_R_NOT_ENOUGH_DATA				 128
#define ASN1_R_NULL_IS_WRONG_LENGTH			 165
#define ASN1_R_ODD_NUMBER_OF_CHARS			 129
#define ASN1_R_PARSING					 130
#define ASN1_R_PRIVATE_KEY_HEADER_MISSING		 131
#define ASN1_R_SECOND_NUMBER_TOO_LARGE			 132
#define ASN1_R_SHORT_LINE				 133
#define ASN1_R_STRING_TOO_LONG				 163
#define ASN1_R_STRING_TOO_SHORT				 134
#define ASN1_R_TAG_VALUE_TOO_HIGH			 135
#define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 136
#define ASN1_R_TOO_LONG					 137
#define ASN1_R_UNABLE_TO_DECODE_RSA_KEY			 138
#define ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY		 139
#define ASN1_R_UNKNOWN_ATTRIBUTE_TYPE			 140
#define ASN1_R_UNKNOWN_FORMAT				 162
#define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM		 141
#define ASN1_R_UNKNOWN_OBJECT_TYPE			 142
#define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE			 143
#define ASN1_R_UNSUPPORTED_CIPHER			 144
#define ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM		 145
#define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE		 146
#define ASN1_R_UTCTIME_TOO_LONG				 147
#define ASN1_R_WRONG_PRINTABLE_TYPE			 148
#define ASN1_R_WRONG_TAG				 149
#define ASN1_R_WRONG_TYPE				 150

#ifdef  __cplusplus
}
#endif
#endif
