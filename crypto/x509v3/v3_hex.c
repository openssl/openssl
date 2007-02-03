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

#include <stdio.h>
#include <ctype.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

/* hex string utilities */

/* Given a buffer of length 'len' return a OPENSSL_malloc'ed string with its
 * hex representation
 * @@@ (Contents of buffer are always kept in ASCII, also on EBCDIC machines)
 */

char *hex_to_string(unsigned char *buffer, long len)
{
	char *tmp, *q;
	unsigned char *p;
	int i;
	const static char hexdig[] = "0123456789ABCDEF";
	if(!buffer || !len) return NULL;
	if(!(tmp = OPENSSL_malloc(len * 3 + 1))) {
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
#ifdef CHARSET_EBCDIC
	ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

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
	if(!(hexbuf = OPENSSL_malloc(strlen(str) >> 1))) goto err;
	for(p = (unsigned char *)str, q = hexbuf; *p;) {
		ch = *p++;
#ifdef CHARSET_EBCDIC
		ch = os_toebcdic[ch];
#endif
		if(ch == ':') continue;
		cl = *p++;
#ifdef CHARSET_EBCDIC
		cl = os_toebcdic[cl];
#endif
		if(!cl) {
			X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ODD_NUMBER_OF_DIGITS);
			OPENSSL_free(hexbuf);
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
	if(hexbuf) OPENSSL_free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,ERR_R_MALLOC_FAILURE);
	return NULL;

	badhex:
	OPENSSL_free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ILLEGAL_HEX_DIGIT);
	return NULL;

}
