/* crypto/asn1/a_time.c */
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


/* This is an implementation of the ASN1 Time structure which is:
 *    Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * written by Steve Henson.
 */

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include <openssl/asn1.h>

ASN1_TIME *ASN1_TIME_new(void)
{ return M_ASN1_TIME_new(); }

void ASN1_TIME_free(ASN1_TIME *x)
{ M_ASN1_TIME_free(x); }

int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **pp)
	{
#ifdef CHARSET_EBCDIC
	/* KLUDGE! We convert to ascii before writing DER */
	char tmp[24];
	ASN1_STRING tmpstr;

	if(a->type == V_ASN1_UTCTIME || a->type == V_ASN1_GENERALIZEDTIME) {
	    int len;

	    tmpstr = *(ASN1_STRING *)a;
	    len = tmpstr.length;
	    ebcdic2ascii(tmp, tmpstr.data, (len >= sizeof tmp) ? sizeof tmp : len);
	    tmpstr.data = tmp;
	    a = (ASN1_GENERALIZEDTIME *) &tmpstr;
	}
#endif
	if(a->type == V_ASN1_UTCTIME || a->type == V_ASN1_GENERALIZEDTIME)
				return(i2d_ASN1_bytes((ASN1_STRING *)a,pp,
				     a->type ,V_ASN1_UNIVERSAL));
	ASN1err(ASN1_F_I2D_ASN1_TIME,ASN1_R_EXPECTING_A_TIME);
	return -1;
	}


ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, unsigned char **pp, long length)
	{
	unsigned char tag;
	tag = **pp & ~V_ASN1_CONSTRUCTED;
	if(tag == (V_ASN1_UTCTIME|V_ASN1_UNIVERSAL))
					 return d2i_ASN1_UTCTIME(a, pp, length);
	if(tag == (V_ASN1_GENERALIZEDTIME|V_ASN1_UNIVERSAL))
				return d2i_ASN1_GENERALIZEDTIME(a, pp, length);
	ASN1err(ASN1_F_D2I_ASN1_TIME,ASN1_R_EXPECTING_A_TIME);
	return(NULL);
	}


ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t)
	{
	struct tm *ts;
#if defined(THREADS) && !defined(WIN32) && !defined(__CYGWIN32__)
	struct tm data;

	gmtime_r(&t,&data);
	ts=&data; /* should return &data, but doesn't on some systems, so we don't even look at the return value */
#else
	ts=gmtime(&t);
#endif
	if((ts->tm_year >= 50) && (ts->tm_year < 150))
					return ASN1_UTCTIME_set(s, t);
	return ASN1_GENERALIZEDTIME_set(s,t);
	}
