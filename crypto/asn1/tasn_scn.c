/* tasn_scn.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2010.
 */
/* ====================================================================
 * Copyright (c) 2010 The OpenSSL Project.  All rights reserved.
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


#include <stddef.h>
#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "asn1_locl.h"

/* General ASN1 structure recursive scanner: iterate through all
 * fields passing details to a callback.
 */

ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb)(ASN1_SCTX *ctx))
	{
	ASN1_SCTX *ret;
	ret = OPENSSL_malloc(sizeof(ASN1_SCTX));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_SCTX_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	ret->scan_cb = scan_cb;
	return ret;
	}

void ASN1_SCTX_free(ASN1_SCTX *p)
	{
	OPENSSL_free(p);
	}

const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p)
	{
	return p->it;
	}

const ASN1_TEMPLATE * ASN1_SCTX_get_template(ASN1_SCTX *p)
	{
	return p->tt;
	}

unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p)
	{
	return p->flags;
	}

void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data)
	{
	p->app_data = data;
	}

void *ASN1_SCTX_get_app_data(ASN1_SCTX *p)
	{
	return p->app_data;
	}
