/* ssl/t1_ext.c */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

/* Custom extension utility functions */

#include "ssl_locl.h"

#ifndef OPENSSL_NO_TLSEXT

/* Find a custom extension from the list */

static custom_ext_method *custom_ext_find(custom_ext_methods *exts,
						unsigned short ext_type)
	{
	size_t i;
	custom_ext_method *meth = exts->meths;
	for (i = 0; i < exts->meths_count; i++, meth++)
		{
		if (ext_type == meth->ext_type)
			return meth;
		}
	return NULL;
	}

/* pass received custom extension data to the application for parsing */

int custom_ext_parse(SSL *s, int server,
			unsigned short ext_type,
			const unsigned char *ext_data, 
			unsigned short ext_size,
			int *al)
	{
	custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
	custom_ext_method *meth;
	meth = custom_ext_find(exts, ext_type);
	/* If not found or no parse function set, return success */
	if (!meth || !meth->parse_cb)
		return 1;

	return meth->parse_cb(s, ext_type, ext_data, ext_size, al, meth->arg);
	}

/* request custom extension data from the application and add to the
 * return buffer
 */

int custom_ext_add(SSL *s, int server,
			unsigned char **pret,
			unsigned char *limit,
			int *al)
	{
	custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
	custom_ext_method *meth;
	unsigned char *ret = *pret;
	size_t i;

	for (i = 0; i < exts->meths_count; i++)
		{
		const unsigned char *out = NULL;
		unsigned short outlen = 0;
		meth = exts->meths + i;

		/* For servers no callback omits extension,
		 * For clients it sends empty extension.
		 */
		if (server && !meth->add_cb)
			continue;
		if (meth->add_cb)
			{
			int cb_retval = 0;
			cb_retval = meth->add_cb(s, meth->ext_type,
							&out, &outlen, al,
							meth->arg);
			if (cb_retval == 0)
				return 0; /* error */
			if (cb_retval == -1)
					continue; /* skip this extension */
			}
		if (4 > limit - ret || outlen > limit - ret - 4)
			return 0;
		s2n(meth->ext_type, ret);
		s2n(outlen, ret);
		if (outlen)
			{
			memcpy(ret, out, outlen);
			ret += outlen;
			}
		}
	*pret = ret;
	return 1;
	}

/* Copy table of custom extensions */

int custom_exts_copy(custom_ext_methods *dst, const custom_ext_methods *src)
	{
	if (src->meths_count)
		{
		dst->meths = BUF_memdup(src->meths, sizeof(custom_ext_method) * src->meths_count);
		if (dst->meths == NULL)
			return 0;
		dst->meths_count = src->meths_count;
		}
	return 1;
	}

void custom_exts_free(custom_ext_methods *exts)
	{
	if (exts->meths)
		OPENSSL_free(exts->meths);
	}

/* Set callbacks for a custom extension */
static int custom_ext_set(custom_ext_methods *exts,
			unsigned short ext_type,
			custom_ext_parse_cb parse_cb,
			custom_ext_add_cb add_cb,
			void *arg)
	{
	custom_ext_method *meth;
	/* Search for duplicate */
	if (custom_ext_find(exts, ext_type))
		return 0;
	exts->meths = OPENSSL_realloc(exts->meths,
					(exts->meths_count + 1) * sizeof(custom_ext_method));

	if (!exts->meths)
		{
		exts->meths_count = 0;
		return 0;
		}

	meth = exts->meths + exts->meths_count;
	meth->parse_cb = parse_cb;
	meth->add_cb = add_cb;
	meth->ext_type = ext_type;
	meth->arg = arg;
	exts->meths_count++;
	return 1;
	}

/* Application level functions to add custom extension callbacks */

int SSL_CTX_set_custom_cli_ext(SSL_CTX *ctx, unsigned short ext_type,
			       custom_cli_ext_first_cb_fn fn1, 
			       custom_cli_ext_second_cb_fn fn2, void *arg)
	{
	return custom_ext_set(&ctx->cert->cli_ext, ext_type, fn2, fn1, arg);
	}

int SSL_CTX_set_custom_srv_ext(SSL_CTX *ctx, unsigned short ext_type,
			       custom_srv_ext_first_cb_fn fn1, 
			       custom_srv_ext_second_cb_fn fn2, void *arg)
	{
	return custom_ext_set(&ctx->cert->srv_ext, ext_type, fn1, fn2, arg);
	}
#endif
