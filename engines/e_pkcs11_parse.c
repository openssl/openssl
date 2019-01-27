/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2017 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "e_pkcs11.h"
#include <stdio.h>
#include <string.h>

static int hex_to_bin(ENGINE_CTX *ctx,
		const char *in, unsigned char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				ctx_log(ctx, 0,
					"hex_to_bin(): invalid char '%c' in hex string\n",
					c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left == 0) {
			ctx_log(ctx, 0, "hex_to_bin(): hex string too long\n");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char)byte;
		left--;
	}

	*outlen = count;
	return 1;
}

/* parse string containing slot and id information */
int parse_slot_id_string(ENGINE_CTX *ctx,
		const char *slot_id, int *slot,
		unsigned char *id, size_t *id_len, char **label)
{
	int n, i;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is undefined) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i, id, id_len);
	}

	/* third: id_<id>, slot is undefined */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id + 3, id, id_len);
	}

	/* label_<label>, slot is undefined */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*slot = -1;
		*label = OPENSSL_strdup(slot_id + 6);
		*id_len = 0;
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		ctx_log(ctx, 0, "Format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		ctx_log(ctx, 0, "Could not decode slot number!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-') {
		ctx_log(ctx, 0, "Could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		*label = OPENSSL_strdup(slot_id + i + 6);
		*id_len = 0;
		return *label != NULL;
	}

	ctx_log(ctx, 0, "Could not parse string!\n");
	return 0;
}

static int parse_uri_attr(ENGINE_CTX *ctx,
		const char *attr, int attrlen, unsigned char **field,
		size_t *field_len)
{
	size_t max, outlen = 0;
	unsigned char *out;
	int ret = 1;

	if (field_len) {
		out = *field;
		max = *field_len;
	} else {
		out = OPENSSL_malloc(attrlen + 1);
		if (out == NULL)
			return 0;
		max = attrlen + 1;
	}

	while (ret && attrlen && outlen < max) {
		if (*attr == '%') {
			if (attrlen < 3) {
				ret = 0;
			} else {
				char tmp[3];
				size_t l = 1;

				tmp[0] = attr[1];
				tmp[1] = attr[2];
				tmp[2] = 0;
				ret = hex_to_bin(ctx, tmp, &out[outlen++], &l);
				attrlen -= 3;
				attr += 3;
			}

		} else {
			out[outlen++] = *(attr++);
			attrlen--;
		}
	}
	if (attrlen && outlen == max)
		ret = 0;

	if (ret) {
		if (field_len) {
			*field_len = outlen;
		} else {
			out[outlen] = 0;
			*field = out;
		}
	} else {
		if (field_len == NULL)
			OPENSSL_free(out);
	}

	return ret;
}

int parse_pkcs11_uri(ENGINE_CTX *ctx,
		const char *uri, PKCS11_TOKEN **p_tok,
		unsigned char *id, size_t *id_len, char *pin, size_t *pin_len,
		char **label)
{
	PKCS11_TOKEN *tok;
	char *newlabel = NULL;
	const char *end, *p;
	int rv = 1, id_set = 0, pin_set = 0;

	tok = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
	if (tok == NULL) {
		ctx_log(ctx, 0, "Could not allocate memory for token info\n");
		return 0;
	}
	memset(tok, 0, sizeof(PKCS11_TOKEN));

	/* We are only ever invoked if the string starts with 'pkcs11:' */
	end = uri + 6;
	while (rv && end[0] && end[1]) {
		p = end + 1;
		end = strpbrk(p, ";?&");
		if (end == NULL)
			end = p + strlen(p);

		if (!strncmp(p, "model=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->model, NULL);
		} else if (!strncmp(p, "manufacturer=", 13)) {
			p += 13;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->manufacturer, NULL);
		} else if (!strncmp(p, "token=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->label, NULL);
		} else if (!strncmp(p, "serial=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->serialnr, NULL);
		} else if (!strncmp(p, "object=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&newlabel, NULL);
		} else if (!strncmp(p, "id=", 3)) {
			p += 3;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&id, id_len);
			id_set = 1;
		} else if (!strncmp(p, "pin-value=", 10)) {
			p += 10;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&pin, pin_len);
			pin_set = 1;
		} else if (!strncmp(p, "type=", 5) || !strncmp(p, "object-type=", 12)) {
			p = strchr(p, '=') + 1;

			if ((end - p == 4 && !strncmp(p, "cert", 4)) ||
					(end - p == 6 && !strncmp(p, "public", 6)) ||
					(end - p == 7 && !strncmp(p, "private", 7))) {
				/* Actually, just ignore it */
			} else {
				ctx_log(ctx, 0, "Unknown object type\n");
				rv = 0;
			}
		} else {
			rv = 0;
		}
	}

	if (!id_set)
		*id_len = 0;
	if (!pin_set)
		*pin_len = 0;

	if (rv) {
		*label = newlabel;
		*p_tok = tok;
	} else {
		OPENSSL_free(tok);
		tok = NULL;
		OPENSSL_free(newlabel);
	}

	return rv;
}

/* vim: set noexpandtab: */
