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
typedef STACK * (*X509V3_EXT_I2V)(struct v3_ext_method *method, char *ext);
typedef char * (*X509V3_EXT_V2I)(struct v3_ext_method *method, struct v3_ext_ctx *ctx, STACK *values);
typedef char * (*X509V3_EXT_I2S)(struct v3_ext_method *method, char *ext);
typedef char * (*X509V3_EXT_S2I)(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *str);
typedef int (*X509V3_EXT_I2R)(struct v3_ext_method *method, char *ext, BIO *out);

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

/* The following is used for raw extensions */
X509V3_EXT_I2R i2r;

char *usr_data;	/* Any extension specific data */
};

/* Context specific info */
struct v3_ctx_struct {
X509 *issuer_cert;
X509 *subject_cert;
X509_REQ *subject_req;
/* Maybe more here */
};

typedef struct v3_ext_method X509V3_EXT_METHOD;
typedef struct v3_ext_ctx X509V3_CTX;

/* ext_flags values */
#define X509V3_EXT_DYNAMIC 0x1

typedef struct {
int bitnum;
char *lname;
char *sname;
} BIT_STRING_BITNAME;

typedef struct {
int ca;
ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;

#define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);

#define EXT_BITSTRING(nid, table) { nid, 0, \
			(X509V3_EXT_NEW)asn1_bit_string_new, ASN1_STRING_free, \
			(X509V3_EXT_D2I)d2i_ASN1_BIT_STRING, \
			i2d_ASN1_BIT_STRING, \
			NULL, NULL, \
			(X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
			(X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
			NULL, \
			(char *)table}

#define EXT_IA5STRING(nid) { nid, 0, \
			(X509V3_EXT_NEW)ia5string_new, ASN1_STRING_free, \
			(X509V3_EXT_D2I)d2i_ASN1_IA5STRING, \
			i2d_ASN1_IA5STRING, \
			(X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
			(X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
			NULL, NULL, NULL, \
			NULL}

#define EXT_END { -1, 0, NULL, NULL, NULL, NULL, NULL, NULL, \
			 NULL, NULL, NULL, \
			 NULL}

#ifndef NOPROTO
void ERR_load_X509V3_strings(void);
void ERR_X509V3_error(int function, int reason, char *file, int line);
int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a, unsigned char **pp);
BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, unsigned char **pp, long length);
BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void);
void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);

int i2d_ext_ku(STACK *a, unsigned char **pp);
STACK *d2i_ext_ku(STACK **a, unsigned char **pp, long length);
void ext_ku_free(STACK *a);
STACK *ext_ku_new(void);

#ifdef HEADER_CONF_H
void X509V3_conf_free(CONF_VALUE *val);
X509_EXTENSION *X509V3_EXT_conf_nid(LHASH *conf, X509V3_CTX *ctx, int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_conf(LHASH *conf, X509V3_CTX *ctx, char *name, char *value);
int X509V3_EXT_add_conf(LHASH *conf, X509V3_CTX *ctx, char *section, X509 *cert);
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint);
#endif

int X509V3_add_value(char *name, char *value, STACK **extlist);
int X509V3_add_value_bool(char *name, int asn1_bool, STACK **extlist);
int X509V3_add_value_int( char *name, ASN1_INTEGER *aint, STACK **extlist);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);

X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
STACK *X509V3_parse_list(char *line);

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, int flag);
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag);

#else

void ERR_load_X509V3_strings();
void ERR_X509V3_error();
int i2d_BASIC_CONSTRAINTS();
BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS();
BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new();
void BASIC_CONSTRAINTS_free();

int i2d_ext_ku();
STACK *d2i_ext_ku();
void ext_ku_free();
STACK *ext_ku_new();

#ifdef HEADER_CONF_H
void X509V3_conf_free();
X509_EXTENSION *X509V3_EXT_conf_nid();
X509_EXTENSION *X509V3_EXT_conf();
int X509V3_EXT_add_conf();
int X509V3_get_value_bool();
int X509V3_get_value_int();
#endif

int X509V3_add_value();
int X509V3_add_value_bool();
int X509V3_add_value_int();
int X509V3_EXT_add();
int X509V3_EXT_add_alias();
void X509V3_EXT_cleanup();

X509V3_EXT_METHOD *X509V3_EXT_get();
X509V3_EXT_METHOD *X509V3_EXT_get_nid();
int X509V3_add_standard_extensions();
STACK *X509V3_parse_list();

int X509V3_EXT_print();
int X509V3_EXT_print_fp();
#endif

/* BEGIN ERROR CODES */
/* Error codes for the X509V3 functions. */

/* Function codes. */
#define X509V3_F_S2I_ASN1_IA5STRING			 100
#define X509V3_F_V2I_ASN1_BIT_STRING			 101
#define X509V3_F_V2I_BASIC_CONSTRAINTS			 102
#define X509V3_F_V2I_EXT_KU				 103
#define X509V3_F_X509V3_ADD_EXT				 104
#define X509V3_F_X509V3_ADD_VALUE			 105
#define X509V3_F_X509V3_EXT_ADD_ALIAS			 106
#define X509V3_F_X509V3_EXT_CONF			 107
#define X509V3_F_X509V3_GET_VALUE_INT			 108
#define X509V3_F_X509V3_PARSE_LIST			 109
#define X509V3_F_X509V3_VALUE_GET_BOOL			 110

/* Reason codes. */
#define X509V3_R_BN_DEC2BN_ERROR			 100
#define X509V3_R_BN_TO_ASN1_INTEGER_ERROR		 101
#define X509V3_R_EXTENSION_NOT_FOUND			 102
#define X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED	 103
#define X509V3_R_INVALID_BOOLEAN_STRING			 104
#define X509V3_R_INVALID_EXTENSION_STRING		 105
#define X509V3_R_INVALID_NAME				 106
#define X509V3_R_INVALID_NULL_ARGUMENT			 107
#define X509V3_R_INVALID_NULL_NAME			 108
#define X509V3_R_INVALID_NULL_VALUE			 109
#define X509V3_R_INVALID_OBJECT_IDENTIFIER		 110
#define X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT		 111
 
#ifdef  __cplusplus
}
#endif
#endif

