/* x509v3.h */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#ifndef HEADER_X509V3_H
#define HEADER_X509V3_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bio.h"
#include "x509.h"

/* Forward reference */
struct v3_ext_method;
struct v3_ext_ctx;

/* Useful typedefs */

typedef char * (*X509V3_EXT_NEW)();
typedef void (*X509V3_EXT_FREE)();
typedef char * (*X509V3_EXT_D2I)();
typedef int (*X509V3_EXT_I2D)();
typedef STACK * (*X509V3_EXT_I2V)(struct v3_ext_method *method, char *ext, STACK *extlist);
typedef char * (*X509V3_EXT_V2I)(struct v3_ext_method *method, struct v3_ext_ctx *ctx, STACK *values);
typedef char * (*X509V3_EXT_I2S)(struct v3_ext_method *method, char *ext);
typedef char * (*X509V3_EXT_S2I)(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *str);
typedef int (*X509V3_EXT_I2R)(struct v3_ext_method *method, char *ext, BIO *out);
typedef char *(*X509V3_EXT_R2I)(struct v3_ext_method *method, char *db, char *value);

/* V3 extension structure */

struct v3_ext_method {
int ext_nid;
int ext_flags;
X509V3_EXT_NEW ext_new;
X509V3_EXT_FREE ext_free;
X509V3_EXT_D2I d2i;
X509V3_EXT_I2D i2d;

/* The following pair is used for string extensions */
X509V3_EXT_I2S i2s;
X509V3_EXT_S2I s2i;

/* The following pair is used for multi-valued extensions */
X509V3_EXT_I2V i2v;
X509V3_EXT_V2I v2i;

/* The following are used for raw extensions */
X509V3_EXT_I2R i2r;
X509V3_EXT_R2I r2i;	/* Doesn't do anything *YET* */

char *usr_data;	/* Any extension specific data */
};


/* Context specific info */
struct v3_ext_ctx {
#define CTX_TEST 0x1
int flags;
X509 *issuer_cert;
X509 *subject_cert;
X509_REQ *subject_req;
X509_CRL *crl;
/* Maybe more here */
};

typedef struct v3_ext_method X509V3_EXT_METHOD;
typedef struct v3_ext_ctx X509V3_CTX;

/* ext_flags values */
#define X509V3_EXT_DYNAMIC 0x1
#define X509V3_EXT_CTX_DEP 0x2

typedef struct {
int bitnum;
char *lname;
char *sname;
} BIT_STRING_BITNAME;

typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

typedef struct {
int ca;
ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;

typedef struct {
ASN1_OCTET_STRING *keyid;
STACK *issuer;
ASN1_INTEGER *serial;
} AUTHORITY_KEYID;

typedef struct {
ASN1_GENERALIZEDTIME *notBefore;
ASN1_GENERALIZEDTIME *notAfter;
} PKEY_USAGE_PERIOD;

typedef struct {

#define GEN_OTHERNAME	(0|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_EMAIL	(1|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_DNS		(2|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_X400	(3|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_DIRNAME	(4|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_EDIPARTY	(5|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_URI		(6|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_IPADD	(7|V_ASN1_CONTEXT_SPECIFIC)
#define GEN_RID		(8|V_ASN1_CONTEXT_SPECIFIC)

int type;
union {
	char *ptr;
	ASN1_IA5STRING *ia5;/* rfc822Name, dNSName, uniformResourceIdentifier */
	ASN1_OCTET_STRING *ip; /* iPAddress */
	X509_NAME *dirn;		/* dirn */
	ASN1_OBJECT *rid; /* registeredID */
	ASN1_TYPE *other; /* otherName, ediPartyName, x400Address */
} d;
} GENERAL_NAME;




#define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);

#define EXT_BITSTRING(nid, table) { nid, 0, \
			(X509V3_EXT_NEW)asn1_bit_string_new, ASN1_STRING_free, \
			(X509V3_EXT_D2I)d2i_ASN1_BIT_STRING, \
			i2d_ASN1_BIT_STRING, \
			NULL, NULL, \
			(X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
			(X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
			NULL, NULL, \
			(char *)table}

#define EXT_IA5STRING(nid) { nid, 0, \
			(X509V3_EXT_NEW)ia5string_new, ASN1_STRING_free, \
			(X509V3_EXT_D2I)d2i_ASN1_IA5STRING, \
			i2d_ASN1_IA5STRING, \
			(X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
			(X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
			NULL, NULL, NULL, NULL, \
			NULL}

#define EXT_END { -1, 0, NULL, NULL, NULL, NULL, NULL, NULL, \
			 NULL, NULL, NULL, NULL, \
			 NULL}

#ifndef NOPROTO
void ERR_load_X509V3_strings(void);
int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a, unsigned char **pp);
BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, unsigned char **pp, long length);
BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void);
void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);

int i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **pp);
GENERAL_NAME *d2i_GENERAL_NAME(GENERAL_NAME **a, unsigned char **pp, long length);
GENERAL_NAME *GENERAL_NAME_new(void);
void GENERAL_NAME_free(GENERAL_NAME *a);
STACK *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method, GENERAL_NAME *gen, STACK *ret);

int i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **pp);
AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a, unsigned char **pp, long length);
AUTHORITY_KEYID *AUTHORITY_KEYID_new(void);
void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a);

int i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD *a, unsigned char **pp);
PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a, unsigned char **pp, long length);
PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new(void);
void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a);

STACK *GENERAL_NAMES_new(void);
void GENERAL_NAMES_free(STACK *a);
STACK *d2i_GENERAL_NAMES(STACK **a, unsigned char **pp, long length);
int i2d_GENERAL_NAMES(STACK *a, unsigned char **pp);
STACK *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method, STACK *gen, STACK *extlist);
STACK *v2i_GENERAL_NAMES(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK *nval);

char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *ia5);
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str);

int i2d_ext_ku(STACK *a, unsigned char **pp);
STACK *d2i_ext_ku(STACK **a, unsigned char **pp, long length);
void ext_ku_free(STACK *a);
STACK *ext_ku_new(void);

#ifdef HEADER_CONF_H
GENERAL_NAME *v2i_GENERAL_NAME(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, CONF_VALUE *cnf);
void X509V3_conf_free(CONF_VALUE *val);
X509_EXTENSION *X509V3_EXT_conf_nid(LHASH *conf, X509V3_CTX *ctx, int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_conf(LHASH *conf, X509V3_CTX *ctx, char *name, char *value);
int X509V3_EXT_add_conf(LHASH *conf, X509V3_CTX *ctx, char *section, X509 *cert);
int X509V3_EXT_CRL_add_conf(LHASH *conf, X509V3_CTX *ctx, char *section, X509_CRL *crl);
int X509V3_EXT_check_conf(LHASH *conf, char *section);
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint);
#endif

int X509V3_add_value(char *name, char *value, STACK **extlist);
int X509V3_add_value_bool(char *name, int asn1_bool, STACK **extlist);
int X509V3_add_value_int( char *name, ASN1_INTEGER *aint, STACK **extlist);
char * i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, ASN1_INTEGER *aint);
char * i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
char * i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);

X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
STACK *X509V3_parse_list(char *line);
char *X509V3_EXT_d2i(X509_EXTENSION *ext);

char *hex_to_string(unsigned char *buffer, long len);
unsigned char *string_to_hex(char *str, long *len);
int name_cmp(char *name, char *cmp);

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, int flag);
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag);

#else

void ERR_load_X509V3_strings();
int i2d_BASIC_CONSTRAINTS();
BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS();
BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new();
void BASIC_CONSTRAINTS_free();

int i2d_GENERAL_NAME();
GENERAL_NAME *d2i_GENERAL_NAME();
GENERAL_NAME *GENERAL_NAME_new();
void GENERAL_NAME_free();
STACK *i2v_GENERAL_NAME();
GENERAL_NAME *v2i_GENERAL_NAME();

int i2d_AUTHORITY_KEYID();
AUTHORITY_KEYID *d2i_AUTHORITY_KEYID();
AUTHORITY_KEYID *AUTHORITY_KEYID_new();
void AUTHORITY_KEYID_free();

int i2d_PKEY_USAGE_PERIOD();
PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD();
PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new();
void PKEY_USAGE_PERIOD_free();

STACK *GENERAL_NAMES_new():
void GENERAL_NAMES_free():
STACK *d2i_GENERAL_NAMES();
int i2d_GENERAL_NAMES();
STACK *i2v_GENERAL_NAMES();
STACK *v2i_GENERAL_NAMES();

char *i2s_ASN1_OCTET_STRING();
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING();

int i2d_ext_ku();
STACK *d2i_ext_ku();
void ext_ku_free();
STACK *ext_ku_new();

#ifdef HEADER_CONF_H
void X509V3_conf_free();
X509_EXTENSION *X509V3_EXT_conf_nid();
X509_EXTENSION *X509V3_EXT_conf();
int X509V3_EXT_add_conf();
int X509V3_EXT_check_conf();
int X509V3_get_value_bool();
int X509V3_get_value_int();
#endif

int X509V3_add_value();
int X509V3_add_value_bool();
int X509V3_add_value_int();
char *i2s_ASN1_INTEGER();
char * i2s_ASN1_ENUMERATED();
char * i2s_ASN1_ENUMERATED_TABLE();
int X509V3_EXT_add();
int X509V3_EXT_CRL_add_conf();
int X509V3_EXT_add_alias();
void X509V3_EXT_cleanup();

X509V3_EXT_METHOD *X509V3_EXT_get();
X509V3_EXT_METHOD *X509V3_EXT_get_nid();
int X509V3_add_standard_extensions();
STACK *X509V3_parse_list();
char *X509V3_EXT_d2i();

char *hex_to_string();
unsigned char *string_to_hex();
int name_cmp();

int X509V3_EXT_print();
int X509V3_EXT_print_fp();
#endif

/* BEGIN ERROR CODES */
/* Error codes for the X509V3 functions. */

/* Function codes. */
#define X509V3_F_COPY_EMAIL				 122
#define X509V3_F_COPY_ISSUER				 123
#define X509V3_F_DO_EXT_CONF				 124
#define X509V3_F_HEX_TO_STRING				 111
#define X509V3_F_I2S_ASN1_ENUMERATED			 121
#define X509V3_F_I2S_ASN1_INTEGER			 120
#define X509V3_F_S2I_ASN1_IA5STRING			 100
#define X509V3_F_S2I_ASN1_OCTET_STRING			 112
#define X509V3_F_S2I_ASN1_SKEY_ID			 114
#define X509V3_F_S2I_S2I_SKEY_ID			 115
#define X509V3_F_STRING_TO_HEX				 113
#define X509V3_F_V2I_ASN1_BIT_STRING			 101
#define X509V3_F_V2I_AUTHORITY_KEYID			 119
#define X509V3_F_V2I_BASIC_CONSTRAINTS			 102
#define X509V3_F_V2I_EXT_KU				 103
#define X509V3_F_V2I_GENERAL_NAME			 117
#define X509V3_F_V2I_GENERAL_NAMES			 118
#define X509V3_F_V3_GENERIC_EXTENSION			 116
#define X509V3_F_X509V3_ADD_EXT				 104
#define X509V3_F_X509V3_ADD_VALUE			 105
#define X509V3_F_X509V3_EXT_ADD_ALIAS			 106
#define X509V3_F_X509V3_EXT_CONF			 107
#define X509V3_F_X509V3_GET_VALUE_INT			 108
#define X509V3_F_X509V3_PARSE_LIST			 109
#define X509V3_F_X509V3_VALUE_GET_BOOL			 110

/* Reason codes. */
#define X509V3_R_BAD_IP_ADDRESS				 118
#define X509V3_R_BAD_OBJECT				 119
#define X509V3_R_BN_DEC2BN_ERROR			 100
#define X509V3_R_BN_TO_ASN1_INTEGER_ERROR		 101
#define X509V3_R_ERROR_IN_EXTENSION			 128
#define X509V3_R_EXTENSION_NAME_ERROR			 115
#define X509V3_R_EXTENSION_NOT_FOUND			 102
#define X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED	 103
#define X509V3_R_EXTENSION_VALUE_ERROR			 116
#define X509V3_R_ILLEGAL_HEX_DIGIT			 113
#define X509V3_R_INVALID_BOOLEAN_STRING			 104
#define X509V3_R_INVALID_EXTENSION_STRING		 105
#define X509V3_R_INVALID_NAME				 106
#define X509V3_R_INVALID_NULL_ARGUMENT			 107
#define X509V3_R_INVALID_NULL_NAME			 108
#define X509V3_R_INVALID_NULL_VALUE			 109
#define X509V3_R_INVALID_OBJECT_IDENTIFIER		 110
#define X509V3_R_ISSUER_DECODE_ERROR			 126
#define X509V3_R_MISSING_VALUE				 124
#define X509V3_R_NO_ISSUER_CERTIFICATE			 121
#define X509V3_R_NO_ISSUER_DETAILS			 127
#define X509V3_R_NO_PUBLIC_KEY				 114
#define X509V3_R_NO_SUBJECT_DETAILS			 125
#define X509V3_R_ODD_NUMBER_OF_DIGITS			 112
#define X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS		 122
#define X509V3_R_UNABLE_TO_GET_ISSUER_KEYID		 123
#define X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT		 111
#define X509V3_R_UNKNOWN_EXTENSION			 129
#define X509V3_R_UNKNOWN_EXTENSION_NAME			 130
#define X509V3_R_UNKNOWN_OPTION				 120
#define X509V3_R_UNSUPPORTED_OPTION			 117
 
#ifdef  __cplusplus
}
#endif
#endif

