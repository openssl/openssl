/* v3_utl.c */
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
/* X509 v3 extension utilities */


#include <stdio.h>
#include <ctype.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

static char *strip_spaces(char *name);

/* Add a CONF_VALUE name value pair to stack */

int X509V3_add_value(const char *name, const char *value,
						STACK_OF(CONF_VALUE) **extlist)
{
	CONF_VALUE *vtmp = NULL;
	char *tname = NULL, *tvalue = NULL;
	if(name && !(tname = BUF_strdup(name))) goto err;
	if(value && !(tvalue = BUF_strdup(value))) goto err;;
	if(!(vtmp = (CONF_VALUE *)Malloc(sizeof(CONF_VALUE)))) goto err;
	if(!*extlist && !(*extlist = sk_CONF_VALUE_new(NULL))) goto err;
	vtmp->section = NULL;
	vtmp->name = tname;
	vtmp->value = tvalue;
	if(!sk_CONF_VALUE_push(*extlist, vtmp)) goto err;
	return 1;
	err:
	X509V3err(X509V3_F_X509V3_ADD_VALUE,ERR_R_MALLOC_FAILURE);
	if(vtmp) Free(vtmp);
	if(tname) Free(tname);
	if(tvalue) Free(tvalue);
	return 0;
}

int X509V3_add_value_uchar(const char *name, const unsigned char *value,
			   STACK_OF(CONF_VALUE) **extlist)
    {
    return X509V3_add_value(name,(const char *)value,extlist);
    }

/* Free function for STACK_OF(CONF_VALUE) */

void X509V3_conf_free(CONF_VALUE *conf)
{
	if(!conf) return;
	if(conf->name) Free(conf->name);
	if(conf->value) Free(conf->value);
	if(conf->section) Free(conf->section);
	Free((char *)conf);
}

int X509V3_add_value_bool(const char *name, int asn1_bool,
						STACK_OF(CONF_VALUE) **extlist)
{
	if(asn1_bool) return X509V3_add_value(name, "TRUE", extlist);
	return X509V3_add_value(name, "FALSE", extlist);
}

int X509V3_add_value_bool_nf(char *name, int asn1_bool,
						STACK_OF(CONF_VALUE) **extlist)
{
	if(asn1_bool) return X509V3_add_value(name, "TRUE", extlist);
	return 1;
}


char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *method, ASN1_ENUMERATED *a)
{
	BIGNUM *bntmp = NULL;
	char *strtmp = NULL;
	if(!a) return NULL;
	if(!(bntmp = ASN1_ENUMERATED_to_BN(a, NULL)) ||
	    !(strtmp = BN_bn2dec(bntmp)) )
		X509V3err(X509V3_F_I2S_ASN1_ENUMERATED,ERR_R_MALLOC_FAILURE);
	BN_free(bntmp);
	return strtmp;
}

char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *method, ASN1_INTEGER *a)
{
	BIGNUM *bntmp = NULL;
	char *strtmp = NULL;
	if(!a) return NULL;
	if(!(bntmp = ASN1_INTEGER_to_BN(a, NULL)) ||
	    !(strtmp = BN_bn2dec(bntmp)) )
		X509V3err(X509V3_F_I2S_ASN1_INTEGER,ERR_R_MALLOC_FAILURE);
	BN_free(bntmp);
	return strtmp;
}

ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method, char *value)
{
	BIGNUM *bn = NULL;
	ASN1_INTEGER *aint;
	bn = BN_new();
	if(!value) {
		X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_INVALID_NULL_VALUE);
		return 0;
	}
	if(!BN_dec2bn(&bn, value)) {
		X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_BN_DEC2BN_ERROR);
		return 0;
	}

	if(!(aint = BN_to_ASN1_INTEGER(bn, NULL))) {
		X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_BN_TO_ASN1_INTEGER_ERROR);
		return 0;
	}
	BN_free(bn);
	return aint;
}

int X509V3_add_value_int(const char *name, ASN1_INTEGER *aint,
	     STACK_OF(CONF_VALUE) **extlist)
{
	char *strtmp;
	int ret;
	if(!aint) return 1;
	if(!(strtmp = i2s_ASN1_INTEGER(NULL, aint))) return 0;
	ret = X509V3_add_value(name, strtmp, extlist);
	Free(strtmp);
	return ret;
}

int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool)
{
	char *btmp;
	if(!(btmp = value->value)) goto err;
	if(!strcmp(btmp, "TRUE") || !strcmp(btmp, "true")
		 || !strcmp(btmp, "Y") || !strcmp(btmp, "y")
		|| !strcmp(btmp, "YES") || !strcmp(btmp, "yes")) {
		*asn1_bool = 0xff;
		return 1;
	} else if(!strcmp(btmp, "FALSE") || !strcmp(btmp, "false")
		 || !strcmp(btmp, "N") || !strcmp(btmp, "n")
		|| !strcmp(btmp, "NO") || !strcmp(btmp, "no")) {
		*asn1_bool = 0;
		return 1;
	}
	err:
	X509V3err(X509V3_F_X509V3_GET_VALUE_BOOL,X509V3_R_INVALID_BOOLEAN_STRING);
	X509V3_conf_err(value);
	return 0;
}

int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint)
{
	ASN1_INTEGER *itmp;
	if(!(itmp = s2i_ASN1_INTEGER(NULL, value->value))) {
		X509V3_conf_err(value);
		return 0;
	}
	*aint = itmp;
	return 1;
}

#define HDR_NAME	1
#define HDR_VALUE	2

/*#define DEBUG*/

STACK_OF(CONF_VALUE) *X509V3_parse_list(char *line)
{
	char *p, *q, c;
	char *ntmp, *vtmp;
	STACK_OF(CONF_VALUE) *values = NULL;
	char *linebuf;
	int state;
	/* We are going to modify the line so copy it first */
	linebuf = BUF_strdup(line);
	state = HDR_NAME;
	ntmp = NULL;
	/* Go through all characters */
	for(p = linebuf, q = linebuf; (c = *p) && (c!='\r') && (c!='\n'); p++) {

		switch(state) {
			case HDR_NAME:
			if(c == ':') {
				state = HDR_VALUE;
				*p = 0;
				ntmp = strip_spaces(q);
				if(!ntmp) {
					X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_NAME);
					goto err;
				}
				q = p + 1;
			} else if(c == ',') {
				*p = 0;
				ntmp = strip_spaces(q);
				q = p + 1;
#ifdef DEBUG
				printf("%s\n", ntmp);
#endif
				if(!ntmp) {
					X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_NAME);
					goto err;
				}
				X509V3_add_value(ntmp, NULL, &values);
			}
			break ;

			case HDR_VALUE:
			if(c == ',') {
				state = HDR_NAME;
				*p = 0;
				vtmp = strip_spaces(q);
#ifdef DEBUG
				printf("%s\n", ntmp);
#endif
				if(!vtmp) {
					X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_VALUE);
					goto err;
				}
				X509V3_add_value(ntmp, vtmp, &values);
				ntmp = NULL;
				q = p + 1;
			}

		}
	}

	if(state == HDR_VALUE) {
		vtmp = strip_spaces(q);
#ifdef DEBUG
		printf("%s=%s\n", ntmp, vtmp);
#endif
		if(!vtmp) {
			X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_VALUE);
			goto err;
		}
		X509V3_add_value(ntmp, vtmp, &values);
	} else {
		ntmp = strip_spaces(q);
#ifdef DEBUG
		printf("%s\n", ntmp);
#endif
		if(!ntmp) {
			X509V3err(X509V3_F_X509V3_PARSE_LIST, X509V3_R_INVALID_NULL_NAME);
			goto err;
		}
		X509V3_add_value(ntmp, NULL, &values);
	}
Free(linebuf);
return values;

err:
Free(linebuf);
sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
return NULL;

}

/* Delete leading and trailing spaces from a string */
static char *strip_spaces(char *name)
{
	char *p, *q;
	/* Skip over leading spaces */
	p = name;
	while(*p && isspace((unsigned char)*p)) p++;
	if(!*p) return NULL;
	q = p + strlen(p) - 1;
	while((q != p) && isspace((unsigned char)*q)) q--;
	if(p != q) q[1] = 0;
	if(!*p) return NULL;
	return p;
}

/* hex string utilities */

/* Given a buffer of length 'len' return a Malloc'ed string with its
 * hex representation
 */

char *hex_to_string(unsigned char *buffer, long len)
{
	char *tmp, *q;
	unsigned char *p;
	int i;
	static char hexdig[] = "0123456789ABCDEF";
	if(!buffer || !len) return NULL;
	if(!(tmp = Malloc(len * 3 + 1))) {
		X509V3err(X509V3_F_HEX_TO_STRING,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	q = tmp;
	for(i = 0, p = buffer; i < len; i++,p++) {
		*q++ = hexdig[(*p >> 4) & 0xf];
		*q++ = hexdig[*p & 0xf];
		*q++ = ':';
	}
	q[-1] = 0;
	return tmp;
}

/* Give a string of hex digits convert to
 * a buffer
 */

unsigned char *string_to_hex(char *str, long *len)
{
	unsigned char *hexbuf, *q;
	unsigned char ch, cl, *p;
	if(!str) {
		X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_INVALID_NULL_ARGUMENT);
		return NULL;
	}
	if(!(hexbuf = Malloc(strlen(str) >> 1))) goto err;
	for(p = (unsigned char *)str, q = hexbuf; *p;) {
		ch = *p++;
		if(ch == ':') continue;
		cl = *p++;
		if(!cl) {
			X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ODD_NUMBER_OF_DIGITS);
			Free(hexbuf);
			return NULL;
		}
		if(isupper(ch)) ch = tolower(ch);
		if(isupper(cl)) cl = tolower(cl);

		if((ch >= '0') && (ch <= '9')) ch -= '0';
		else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
		else goto badhex;

		if((cl >= '0') && (cl <= '9')) cl -= '0';
		else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
		else goto badhex;

		*q++ = (ch << 4) | cl;
	}

	if(len) *len = q - hexbuf;

	return hexbuf;

	err:
	if(hexbuf) Free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,ERR_R_MALLOC_FAILURE);
	return NULL;

	badhex:
	Free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ILLEGAL_HEX_DIGIT);
	return NULL;

}

/* V2I name comparison function: returns zero if 'name' matches
 * cmp or cmp.*
 */

int name_cmp(const char *name, const char *cmp)
{
	int len, ret;
	char c;
	len = strlen(cmp);
	if((ret = strncmp(name, cmp, len))) return ret;
	c = name[len];
	if(!c || (c=='.')) return 0;
	return 1;
}
