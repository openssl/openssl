/* pk7_mime.c */
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

#include <stdio.h>
#include <ctype.h>
#include "cryptlib.h"
#include <openssl/rand.h>
#include <openssl/x509.h>

/* MIME and related routines */

/* MIME format structures
 * Note that all are translated to lower case apart from
 * parameter values. Quotes are stripped off
 */

typedef struct {
char *name;				/* Name of line e.g. "content-type" */
char *value;				/* Value of line e.g. "text/plain" */
STACK /* MIME_PARAM */ *params;		/* Zero or more parameters */
} MIME_HEADER;

typedef struct {
char *param_name;			/* Param name e.g. "micalg" */
char *param_value;			/* Param value e.g. "sha1" */
} MIME_PARAM;


static int B64_write_PKCS7(BIO *bio, PKCS7 *p7);
static PKCS7 *B64_read_PKCS7(BIO *bio);
static char * strip_ends(char *name);
static char * strip_start(char *name);
static char * strip_end(char *name);
static MIME_HEADER *mime_hdr_new(char *name, char *value);
static int mime_hdr_addparam(MIME_HEADER *mhdr, char *name, char *value);
static STACK *mime_parse_hdr(BIO *bio);
static int mime_hdr_cmp(MIME_HEADER **a, MIME_HEADER **b);
static int mime_param_cmp(MIME_PARAM **a, MIME_PARAM **b);
static void mime_param_free(MIME_PARAM *param);
static int mime_bound_check(char *line, int linelen, char *bound, int blen);
static int multi_split(BIO *bio, char *bound, STACK **ret);
static int iscrlf(char c);
static MIME_HEADER *mime_hdr_find(STACK *hdrs, char *name);
static MIME_PARAM *mime_param_find(MIME_HEADER *hdr, char *name);
static void mime_hdr_free(MIME_HEADER *hdr);

#define MAX_SMLEN 1024
#define mime_debug(x) /* x */


typedef void (*stkfree)();

/* Base 64 read and write of PKCS#7 structure */

static int B64_write_PKCS7(BIO *bio, PKCS7 *p7)
{
	BIO *b64;
	if(!(b64 = BIO_new(BIO_f_base64()))) {
		PKCS7err(PKCS7_F_B64_WRITE_PKCS7,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	bio = BIO_push(b64, bio);
	i2d_PKCS7_bio(bio, p7);
	BIO_flush(bio);
	bio = BIO_pop(bio);
	BIO_free(b64);
	return 1;
}

static PKCS7 *B64_read_PKCS7(BIO *bio)
{
	BIO *b64;
	PKCS7 *p7;
	if(!(b64 = BIO_new(BIO_f_base64()))) {
		PKCS7err(PKCS7_F_B64_READ_PKCS7,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	bio = BIO_push(b64, bio);
	if(!(p7 = d2i_PKCS7_bio(bio, NULL))) 
		PKCS7err(PKCS7_F_B64_READ_PKCS7,PKCS7_R_DECODE_ERROR);
	BIO_flush(bio);
	bio = BIO_pop(bio);
	BIO_free(b64);
	return p7;
}

/* SMIME sender */

int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags)
{
	char linebuf[MAX_SMLEN];
	char bound[33], c;
	int i;
	if((flags & PKCS7_DETACHED) && data) {
	/* We want multipart/signed */
		/* Generate a random boundary */
		RAND_pseudo_bytes((unsigned char *)bound, 32);
		for(i = 0; i < 32; i++) {
			c = bound[i] & 0xf;
			if(c < 10) c += '0';
			else c += 'A' - 10;
			bound[i] = c;
		}
		bound[32] = 0;
		BIO_printf(bio, "MIME-Version: 1.0\n");
		BIO_printf(bio, "Content-Type: multipart/signed ; ");
		BIO_printf(bio, "protocol=\"application/x-pkcs7-signature\" ; ");
		BIO_printf(bio, "micalg=sha1 ; boundary=\"----%s\"\n\n", bound);
		BIO_printf(bio, "This is an S/MIME signed message\n\n");
		/* Now write out the first part */
		BIO_printf(bio, "------%s\r\n", bound);
		if(flags & PKCS7_TEXT) BIO_printf(bio, "Content-Type: text/plain\n\n");
		while((i = BIO_read(data, linebuf, MAX_SMLEN)) > 0) 
						BIO_write(bio, linebuf, i);
		BIO_printf(bio, "\n------%s\n", bound);

		/* Headers for signature */

		BIO_printf(bio, "Content-Type: application/x-pkcs7-signature; name=\"smime.p7s\"\n");
		BIO_printf(bio, "Content-Transfer-Encoding: base64\n");
		BIO_printf(bio, "Content-Disposition: attachment; filename=\"smime.p7s\"\n\n");
		B64_write_PKCS7(bio, p7);
		BIO_printf(bio,"\n------%s--\n\n", bound);
		return 1;
	}
	/* MIME headers */
	BIO_printf(bio, "MIME-Version: 1.0\n");
	BIO_printf(bio, "Content-Disposition: attachment; filename=\"smime.p7m\"\n");
	BIO_printf(bio, "Content-Type: application/x-pkcs7-mime; name=\"smime.p7m\"\n");
	BIO_printf(bio, "Content-Transfer-Encoding: base64\n\n");
	B64_write_PKCS7(bio, p7);
	BIO_printf(bio, "\n");
	return 1;
}

/* SMIME reader: handle multipart/signed and opaque signing.
 * in multipart case the content is placed in a memory BIO
 * pointed to by "bcont". In opaque this is set to NULL
 */

PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont)
{
	BIO *p7in;
	STACK *headers = NULL;
	STACK *parts = NULL;
	MIME_HEADER *hdr;
	MIME_PARAM *prm;
	PKCS7 *p7;
	int ret;

	if(bcont) *bcont = NULL;

	if (!(headers = mime_parse_hdr(bio))) {
		PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_MIME_PARSE_ERROR);
		return NULL;
	}

	if(!(hdr = mime_hdr_find(headers, "content-type")) || !hdr->value) {
		sk_pop_free(headers, mime_hdr_free);
		PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_CONTENT_TYPE);
		return NULL;
	}

	/* Handle multipart/signed */

	if(!strcmp(hdr->value, "multipart/signed")) {
		/* Split into two parts */
		prm = mime_param_find(hdr, "boundary");
		if(!prm || !prm->param_value) {
			sk_pop_free(headers, mime_hdr_free);
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_MULTIPART_BOUNDARY);
			return NULL;
		}
		ret = multi_split(bio, prm->param_value, &parts);
		sk_pop_free(headers, mime_hdr_free);
		if(!ret || (sk_num(parts) != 2) ) {
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_MULTIPART_BODY_FAILURE);
			sk_pop_free(parts, (stkfree)BIO_free);
			return NULL;
		}

		/* Parse the signature piece */
		p7in = (BIO *)sk_value(parts, 1);

		if (!(headers = mime_parse_hdr(p7in))) {
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_MIME_SIG_PARSE_ERROR);
			sk_pop_free(parts, (stkfree)BIO_free);
			return NULL;
		}

		/* Get content type */

		if(!(hdr = mime_hdr_find(headers, "content-type")) ||
								 !hdr->value) {
			sk_pop_free(headers, mime_hdr_free);
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_NO_SIG_CONTENT_TYPE);
			return NULL;
		}

		if(strcmp(hdr->value, "application/x-pkcs7-signature") &&
			strcmp(hdr->value, "application/pkcs7-signature")) {
			sk_pop_free(headers, mime_hdr_free);
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_SIG_INVALID_MIME_TYPE);
			ERR_add_error_data(2, "type: ", hdr->value);
			sk_pop_free(parts, (stkfree)BIO_free);
			return NULL;
		}
		sk_pop_free(headers, mime_hdr_free);
		/* Read in PKCS#7 */
		if(!(p7 = B64_read_PKCS7(p7in))) {
			PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_PKCS7_SIG_PARSE_ERROR);
			sk_pop_free(parts, (stkfree)BIO_free);
			return NULL;
		}

		if(bcont) {
			*bcont = (BIO *)sk_value(parts, 0);
			BIO_free(p7in);
			sk_free(parts);
		} else sk_pop_free(parts, (stkfree)BIO_free);
		return p7;
	}
		
	/* OK, if not multipart/signed try opaque signature */

	if (strcmp (hdr->value, "application/x-pkcs7-mime") &&
	    strcmp (hdr->value, "application/pkcs7-mime")) {
		PKCS7err(PKCS7_F_SMIME_READ_PKCS7,PKCS7_R_INVALID_MIME_TYPE);
		ERR_add_error_data(2, "type: ", hdr->value);
		sk_pop_free(headers, mime_hdr_free);
		return NULL;
	}

	sk_pop_free(headers, mime_hdr_free);
	
	if(!(p7 = B64_read_PKCS7(bio))) {
		PKCS7err(PKCS7_F_SMIME_READ_PKCS7, PKCS7_R_PKCS7_PARSE_ERROR);
		return NULL;
	}
	return p7;

}

/* Copy text from one BIO to another making the output CRLF at EOL */
int SMIME_crlf_copy(BIO *in, BIO *out, int flags)
{
	char eol;
	int len;
	char linebuf[MAX_SMLEN];
	if(flags & PKCS7_BINARY) {
		while((len = BIO_read(in, linebuf, MAX_SMLEN)) > 0)
						BIO_write(out, linebuf, len);
		return 1;
	}
	if(flags & PKCS7_TEXT) BIO_printf(out, "Content-Type: text/plain\r\n\r\n");
	while ((len = BIO_gets(in, linebuf, MAX_SMLEN)) > 0) {
		eol = 0;
		while(iscrlf(linebuf[len - 1])) {
			len--;
			eol = 1;
		}	
		BIO_write(out, linebuf, len);
		if(eol) BIO_write(out, "\r\n", 2);
	}
	return 1;
}

/* Strip off headers if they are text/plain */
int SMIME_text(BIO *in, BIO *out)
{
	char iobuf[4096];
	int len;
	STACK *headers;
	MIME_HEADER *hdr;
	if (!(headers = mime_parse_hdr(in))) {
		PKCS7err(PKCS7_F_SMIME_TEXT,PKCS7_R_MIME_PARSE_ERROR);
		return 0;
	}
	if(!(hdr = mime_hdr_find(headers, "content-type")) || !hdr->value) {
		PKCS7err(PKCS7_F_SMIME_TEXT,PKCS7_R_MIME_NO_CONTENT_TYPE);
		sk_pop_free(headers, mime_hdr_free);
		return 0;
	}
	if (strcmp (hdr->value, "text/plain")) {
		PKCS7err(PKCS7_F_SMIME_TEXT,PKCS7_R_INVALID_MIME_TYPE);
		ERR_add_error_data(2, "type: ", hdr->value);
		sk_pop_free(headers, mime_hdr_free);
		return 0;
	}
	sk_pop_free(headers, mime_hdr_free);
	while ((len = BIO_read(in, iobuf, sizeof(iobuf))) > 0)
						BIO_write(out, iobuf, len);
	return 1;
}

/* Split a multipart/XXX message body into component parts: result is
 * canonical parts in a STACK of bios
 */

static int multi_split(BIO *bio, char *bound, STACK **ret)
{
	char linebuf[MAX_SMLEN];
	int len, blen;
	BIO *bpart = NULL;
	STACK *parts;
	char state, part, first;
	blen = strlen(bound);
	part = 0;
	state = 0;
	first = 1;
	parts = sk_new(NULL);
	*ret = parts;
	while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
		state = mime_bound_check(linebuf, len, bound, blen);
		if(state == 1) {
			first = 1;
			part++;
		} else if(state == 2) {
			sk_push(parts, (char *)bpart);
			return 1;
		} else if(part) {
			if(first) {
				first = 0;
				if(bpart) sk_push(parts, (char *)bpart);
				bpart = BIO_new(BIO_s_mem());
				
			} else BIO_write(bpart, "\r\n", 2);
			/* Strip CR+LF from linebuf */
			while(iscrlf(linebuf[len - 1])) len--;
			BIO_write(bpart, linebuf, len);
		}
	}
	return 0;
}

static int iscrlf(char c)
{
	if(c == '\r' || c == '\n') return 1;
	return 0;
}

/* This is the big one: parse MIME header lines up to message body */

#define MIME_INVALID	0
#define MIME_START	1
#define MIME_TYPE	2
#define MIME_NAME	3
#define MIME_VALUE	4
#define MIME_QUOTE	5
#define MIME_COMMENT	6


static STACK *mime_parse_hdr(BIO *bio)
{
	char *p, *q, c;
	char *ntmp;
	char linebuf[MAX_SMLEN];
	MIME_HEADER *mhdr = NULL;
	STACK *headers;
	int len, state, save_state = 0;
	headers = sk_new(mime_hdr_cmp);
	while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
	/* If whitespace at line start then continuation line */
	if(mhdr && isspace((unsigned char)linebuf[0])) state = MIME_NAME;
	else state = MIME_START;
	ntmp = NULL;
	/* Go through all characters */
	for(p = linebuf, q = linebuf; (c = *p) && (c!='\r') && (c!='\n'); p++) {

	/* State machine to handle MIME headers
	 * if this looks horrible that's because it *is*
         */

		switch(state) {
			case MIME_START:
			if(c == ':') {
				state = MIME_TYPE;
				*p = 0;
				ntmp = strip_ends(q);
				q = p + 1;
			}
			break;

			case MIME_TYPE:
			if(c == ';') {
				mime_debug("Found End Value\n");
				*p = 0;
				mhdr = mime_hdr_new(ntmp, strip_ends(q));
				sk_push(headers, (char *)mhdr);
				ntmp = NULL;
				q = p + 1;
				state = MIME_NAME;
			} else if(c == '(') {
				save_state = state;
				state = MIME_COMMENT;
			}
			break;

			case MIME_COMMENT:
			if(c == ')') {
				state = save_state;
			}
			break;

			case MIME_NAME:
			if(c == '=') {
				state = MIME_VALUE;
				*p = 0;
				ntmp = strip_ends(q);
				q = p + 1;
			}
			break ;

			case MIME_VALUE:
			if(c == ';') {
				state = MIME_NAME;
				*p = 0;
				mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
				ntmp = NULL;
				q = p + 1;
			} else if (c == '"') {
				mime_debug("Found Quote\n");
				state = MIME_QUOTE;
			} else if(c == '(') {
				save_state = state;
				state = MIME_COMMENT;
			}
			break;

			case MIME_QUOTE:
			if(c == '"') {
				mime_debug("Found Match Quote\n");
				state = MIME_VALUE;
			}
			break;
		}
	}

	if(state == MIME_TYPE) {
		mhdr = mime_hdr_new(ntmp, strip_ends(q));
		sk_push(headers, (char *)mhdr);
	} else if(state == MIME_VALUE)
			 mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
	if(p == linebuf) break;	/* Blank line means end of headers */
}

return headers;

}

static char *strip_ends(char *name)
{
	return strip_end(strip_start(name));
}

/* Strip a parameter of whitespace from start of param */
static char *strip_start(char *name)
{
	char *p, c;
	/* Look for first non white space or quote */
	for(p = name; (c = *p) ;p++) {
		if(c == '"') {
			/* Next char is start of string if non null */
			if(p[1]) return p + 1;
			/* Else null string */
			return NULL;
		}
		if(!isspace((unsigned char)c)) return p;
	}
	return NULL;
}

/* As above but strip from end of string : maybe should handle brackets? */
static char *strip_end(char *name)
{
	char *p, c;
	if(!name) return NULL;
	/* Look for first non white space or quote */
	for(p = name + strlen(name) - 1; p >= name ;p--) {
		c = *p;
		if(c == '"') {
			if(p - 1 == name) return NULL;
			*p = 0;
			return name;
		}
		if(isspace((unsigned char)c)) *p = 0;	
		else return name;
	}
	return NULL;
}

static MIME_HEADER *mime_hdr_new(char *name, char *value)
{
	MIME_HEADER *mhdr;
	char *tmpname, *tmpval, *p;
	int c;
	if(name) {
		if(!(tmpname = BUF_strdup(name))) return NULL;
		for(p = tmpname ; *p; p++) {
			c = *p;
			if(isupper(c)) {
				c = tolower(c);
				*p = c;
			}
		}
	} else tmpname = NULL;
	if(value) {
		if(!(tmpval = BUF_strdup(value))) return NULL;
		for(p = tmpval ; *p; p++) {
			c = *p;
			if(isupper(c)) {
				c = tolower(c);
				*p = c;
			}
		}
	} else tmpval = NULL;
	mhdr = (MIME_HEADER *) Malloc(sizeof(MIME_HEADER));
	if(!mhdr) return NULL;
	mhdr->name = tmpname;
	mhdr->value = tmpval;
	if(!(mhdr->params = sk_new(mime_param_cmp))) return NULL;
	return mhdr;
}
		
static int mime_hdr_addparam(MIME_HEADER *mhdr, char *name, char *value)
{
	char *tmpname, *tmpval, *p;
	int c;
	MIME_PARAM *mparam;
	if(name) {
		tmpname = BUF_strdup(name);
		if(!tmpname) return 0;
		for(p = tmpname ; *p; p++) {
			c = *p;
			if(isupper(c)) {
				c = tolower(c);
				*p = c;
			}
		}
	} else tmpname = NULL;
	if(value) {
		tmpval = BUF_strdup(value);
		if(!tmpval) return 0;
	} else tmpval = NULL;
	/* Parameter values are case sensitive so leave as is */
	mparam = (MIME_PARAM *) Malloc(sizeof(MIME_PARAM));
	if(!mparam) return 0;
	mparam->param_name = tmpname;
	mparam->param_value = tmpval;
	sk_push(mhdr->params, (char *)mparam);
	return 1;
}

static int mime_hdr_cmp(MIME_HEADER **a, MIME_HEADER **b)
{
	return(strcmp((*a)->name, (*b)->name));
}

static int mime_param_cmp(MIME_PARAM **a, MIME_PARAM **b)
{
	return(strcmp((*a)->param_name, (*b)->param_name));
}

/* Find a header with a given name (if possible) */

static MIME_HEADER *mime_hdr_find(STACK *hdrs, char *name)
{
	MIME_HEADER htmp;
	int idx;
	htmp.name = name;
	idx = sk_find(hdrs, (char *)&htmp);
	if(idx < 0) return NULL;
	return (MIME_HEADER *)sk_value(hdrs, idx);
}

static MIME_PARAM *mime_param_find(MIME_HEADER *hdr, char *name)
{
	MIME_PARAM param;
	int idx;
	param.param_name = name;
	idx = sk_find(hdr->params, (char *)&param);
	if(idx < 0) return NULL;
	return (MIME_PARAM *)sk_value(hdr->params, idx);
}

static void mime_hdr_free(MIME_HEADER *hdr)
{
	if(hdr->name) Free(hdr->name);
	if(hdr->value) Free(hdr->value);
	if(hdr->params) sk_pop_free(hdr->params, mime_param_free);
	Free(hdr);
}

static void mime_param_free(MIME_PARAM *param)
{
	if(param->param_name) Free(param->param_name);
	if(param->param_value) Free(param->param_value);
	Free(param);
}

/* Check for a multipart boundary. Returns:
 * 0 : no boundary
 * 1 : part boundary
 * 2 : final boundary
 */
static int mime_bound_check(char *line, int linelen, char *bound, int blen)
{
	if(linelen == -1) linelen = strlen(line);
	if(blen == -1) blen = strlen(bound);
	/* Quickly eliminate if line length too short */
	if(blen + 2 > linelen) return 0;
	/* Check for part boundary */
	if(!strncmp(line, "--", 2) && !strncmp(line + 2, bound, blen)) {
		if(!strncmp(line + blen + 2, "--", 2)) return 2;
		else return 1;
	}
	return 0;
}
