/* pmeth_lib.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <openssl/objects.h>
#include "cryptlib.h"
#include "evp_locl.h"

STACK *app_pkey_methods = NULL;

extern EVP_PKEY_METHOD rsa_pkey_meth;

const EVP_PKEY_METHOD *standard_methods[] =
	{
	&rsa_pkey_meth
	};

static int pmeth_cmp(const EVP_PKEY_METHOD * const *a,
                const EVP_PKEY_METHOD * const *b)
	{
        return ((*a)->pkey_id - (*b)->pkey_id);
	}

const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type, ENGINE *e)
	{
	EVP_PKEY_METHOD tmp, *t = &tmp, **ret;
	tmp.pkey_id = type;
	if (app_pkey_methods)
		{
		int idx;
		idx = sk_find(app_pkey_methods, (char *)&tmp);
		if (idx >= 0)
			return (EVP_PKEY_METHOD *)
				sk_value(app_pkey_methods, idx);
		}
	ret = (EVP_PKEY_METHOD **) OBJ_bsearch((char *)&t,
        		(char *)standard_methods,
			sizeof(standard_methods)/sizeof(EVP_PKEY_METHOD *),
        		sizeof(EVP_PKEY_METHOD *),
			(int (*)(const void *, const void *))pmeth_cmp);
	if (!ret || !*ret)
		return NULL;
	return *ret;
	}

EVP_PKEY_CTX *EVP_PKEY_CTX_new(int ktype, ENGINE *e)
	{
	EVP_PKEY_CTX *ret;
	const EVP_PKEY_METHOD *pmeth;
	pmeth = EVP_PKEY_meth_find(ktype, e);
	if (pmeth == NULL)
		return NULL;
	ret = OPENSSL_malloc(sizeof(EVP_PKEY_CTX));
	ret->pmeth = pmeth;
	ret->operation = EVP_PKEY_OP_UNDEFINED;
	ret->pkey = NULL;
	ret->data = NULL;

	return ret;
	}

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
				int cmd, int p1, void *p2)
	{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl)
		return -2;
	if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
		return -1;

	if (ctx->operation == EVP_PKEY_OP_UNDEFINED)
		{
		/* Not initialized */
		return -1;
		}

	if ((optype != -1) && (ctx->operation != optype))
		{
		/* Invalid operation type */
		return -1;
		}

	return ctx->pmeth->ctrl(ctx, cmd, p1, p2);

	}






