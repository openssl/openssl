/* $OpenBSD: a_time.c,v 1.20 2014/07/10 13:58:22 jsing Exp $ */
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
#include <string.h>
#include <time.h>

#include <openssl/asn1t.h>
#include <openssl/err.h>

#include "o_time.h"

IMPLEMENT_ASN1_MSTRING(ASN1_TIME, B_ASN1_TIME)

IMPLEMENT_ASN1_FUNCTIONS(ASN1_TIME)

#if 0
int
i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **pp)
{
	if (a->type == V_ASN1_UTCTIME || a->type == V_ASN1_GENERALIZEDTIME)
		return(i2d_ASN1_bytes((ASN1_STRING *)a, pp,
		    a->type, V_ASN1_UNIVERSAL));
	ASN1err(ASN1_F_I2D_ASN1_TIME, ASN1_R_EXPECTING_A_TIME);
	return -1;
}
#endif

ASN1_TIME *
ASN1_TIME_set(ASN1_TIME *s, time_t t)
{
	return ASN1_TIME_adj(s, t, 0, 0);
}

ASN1_TIME *
ASN1_TIME_adj(ASN1_TIME *s, time_t t, int offset_day, long offset_sec)
{
	struct tm *ts;
	struct tm data;

	ts = gmtime_r(&t, &data);
	if (ts == NULL) {
		ASN1err(ASN1_F_ASN1_TIME_ADJ, ASN1_R_ERROR_GETTING_TIME);
		return NULL;
	}
	if (offset_day || offset_sec) {
		if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
			return NULL;
	}
	if ((ts->tm_year >= 50) && (ts->tm_year < 150))
		return ASN1_UTCTIME_adj(s, t, offset_day, offset_sec);
	return ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec);
}

int
ASN1_TIME_check(ASN1_TIME *t)
{
	if (t->type == V_ASN1_GENERALIZEDTIME)
		return ASN1_GENERALIZEDTIME_check(t);
	else if (t->type == V_ASN1_UTCTIME)
		return ASN1_UTCTIME_check(t);
	return 0;
}

/* Convert an ASN1_TIME structure to GeneralizedTime */
static ASN1_GENERALIZEDTIME *
ASN1_TIME_to_generalizedtime_internal(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out)
{
	ASN1_GENERALIZEDTIME *ret;
	char *str;
	int newlen;
	int i;

	if (!ASN1_TIME_check(t))
		return NULL;

	ret = *out;

	/* If already GeneralizedTime just copy across */
	if (t->type == V_ASN1_GENERALIZEDTIME) {
		if (!ASN1_STRING_set(ret, t->data, t->length))
			return NULL;
		return ret;
	}

	/* grow the string */
	if (!ASN1_STRING_set(ret, NULL, t->length + 2))
		return NULL;
	/* ASN1_STRING_set() allocated 'len + 1' bytes. */
	newlen = t->length + 2 + 1;
	str = (char *)ret->data;
	/* XXX ASN1_TIME is not Y2050 compatible */
	i = snprintf(str, newlen, "%s%s", (t->data[0] >= '5') ? "19" : "20",
	    (char *) t->data);
	if (i == -1 || i >= newlen) {
		M_ASN1_GENERALIZEDTIME_free(ret);
		*out = NULL;
		return NULL;
	}
	return ret;
}

ASN1_GENERALIZEDTIME *
ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out)
{
	ASN1_GENERALIZEDTIME *tmp = NULL, *ret;

	if (!out || !*out) {
		if (!(tmp = ASN1_GENERALIZEDTIME_new()))
			return NULL;
		if (out != NULL)
			*out = tmp;
		else
			out = &tmp;
	}

	ret = ASN1_TIME_to_generalizedtime_internal(t, out);
	if (ret == NULL && tmp != NULL)
		ASN1_GENERALIZEDTIME_free(tmp);

	return ret;
}

int
ASN1_TIME_set_string(ASN1_TIME *s, const char *str)
{
	ASN1_TIME t;

	t.length = strlen(str);
	t.data = (unsigned char *)str;
	t.flags = 0;

	t.type = V_ASN1_UTCTIME;

	if (!ASN1_TIME_check(&t)) {
		t.type = V_ASN1_GENERALIZEDTIME;
		if (!ASN1_TIME_check(&t))
			return 0;
	}

	if (s && !ASN1_STRING_copy((ASN1_STRING *)s, (ASN1_STRING *)&t))
		return 0;

	return 1;
}
