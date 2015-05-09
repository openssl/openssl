/* $OpenBSD: a_utctm.c,v 1.26 2014/07/10 13:58:22 jsing Exp $ */
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
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/err.h>

#include "o_time.h"

int
ASN1_UTCTIME_check(ASN1_UTCTIME *d)
{
	static const int min[8] = {0, 1, 1, 0, 0, 0, 0, 0};
	static const int max[8] = {99, 12, 31, 23, 59, 59, 12, 59};
	char *a;
	int n, i, l, o;

	if (d->type != V_ASN1_UTCTIME)
		return (0);
	l = d->length;
	a = (char *)d->data;
	o = 0;

	if (l < 11)

		goto err;
	for (i = 0; i < 6; i++) {
		if ((i == 5) && ((a[o] == 'Z') ||
		    (a[o] == '+') || (a[o] == '-'))) {
			i++;
			break;
		}
		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = a[o]-'0';
		if (++o > l)
			goto err;
		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = (n * 10) + a[o] - '0';
		if (++o > l)
			goto err;
		if ((n < min[i]) || (n > max[i]))
			goto err;
	}
	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-')) {
		o++;
		if (o + 4 > l)
			goto err;
		for (i = 6; i < 8; i++) {
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = a[o] -'0';
			o++;
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = (n * 10) + a[o] - '0';
			if ((n < min[i]) || (n > max[i]))
				goto err;
			o++;
		}
	}
	return (o == l);

err:
	return (0);
}

int
ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str)
{
	ASN1_UTCTIME t;

	t.type = V_ASN1_UTCTIME;
	t.length = strlen(str);
	t.data = (unsigned char *)str;
	if (ASN1_UTCTIME_check(&t)) {
		if (s != NULL) {
			if (!ASN1_STRING_set((ASN1_STRING *)s,
			    (unsigned char *)str, t.length))
				return 0;
			s->type = V_ASN1_UTCTIME;
		}
		return (1);
	} else
		return (0);
}

ASN1_UTCTIME *
ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t)
{
	return ASN1_UTCTIME_adj(s, t, 0, 0);
}

static ASN1_UTCTIME *
ASN1_UTCTIME_adj_internal(ASN1_UTCTIME *s, time_t t, int offset_day,
    long offset_sec)
{
	char *p;
	struct tm *ts;
	struct tm data;
	size_t len = 20;

	ts = gmtime_r(&t, &data);
	if (ts == NULL)
		return (NULL);

	if (offset_day || offset_sec) {
		if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
			return NULL;
	}

	if ((ts->tm_year < 50) || (ts->tm_year >= 150))
		return NULL;

	p = (char *)s->data;
	if ((p == NULL) || ((size_t)s->length < len)) {
		p = malloc(len);
		if (p == NULL) {
			ASN1err(ASN1_F_ASN1_UTCTIME_ADJ, ERR_R_MALLOC_FAILURE);
			return (NULL);
		}
		free(s->data);
		s->data = (unsigned char *)p;
	}

	snprintf(p, len, "%02d%02d%02d%02d%02d%02dZ", ts->tm_year % 100,
	    ts->tm_mon + 1, ts->tm_mday, ts->tm_hour, ts->tm_min, ts->tm_sec);
	s->length = strlen(p);
	s->type = V_ASN1_UTCTIME;
	return (s);
}

ASN1_UTCTIME *
ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t, int offset_day, long offset_sec)
{
	ASN1_UTCTIME *tmp = NULL, *ret;

	if (s == NULL) {
		tmp = M_ASN1_UTCTIME_new();
		if (tmp == NULL)
			return NULL;
		s = tmp;
	}

	ret = ASN1_UTCTIME_adj_internal(s, t, offset_day, offset_sec);
	if (ret == NULL && tmp != NULL)
		M_ASN1_UTCTIME_free(tmp);

	return ret;
}

int
ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t)
{
	struct tm *tm;
	struct tm data;
	int offset;
	int year;

#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')

	if (s->data[12] == 'Z')
		offset = 0;
	else {
		offset = g2(s->data + 13)*60 + g2(s->data + 15);
		if (s->data[12] == '-')
			offset = -offset;
	}

	t -= offset * 60; /* FIXME: may overflow in extreme cases */

	tm = gmtime_r(&t, &data);

#define return_cmp(a,b) if ((a)<(b)) return -1; else if ((a)>(b)) return 1
	year = g2(s->data);
	if (year < 50)
		year += 100;
	return_cmp(year, tm->tm_year);
	return_cmp(g2(s->data + 2) - 1, tm->tm_mon);
	return_cmp(g2(s->data + 4), tm->tm_mday);
	return_cmp(g2(s->data + 6), tm->tm_hour);
	return_cmp(g2(s->data + 8), tm->tm_min);
	return_cmp(g2(s->data + 10), tm->tm_sec);
#undef g2
#undef return_cmp

	return 0;
}
