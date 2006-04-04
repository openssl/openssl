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
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/dh.h>
#include "asn1_locl.h"

static void int_dh_free(EVP_PKEY *pkey)
	{
	DH_free(pkey->pkey.dh);
	}

static int dh_param_decode(EVP_PKEY *pkey,
					const unsigned char **pder, int derlen)
	{
	DH *dh;
	if (!(dh = d2i_DHparams(NULL, pder, derlen)))
		{
		DHerr(DH_F_DH_PARAM_DECODE, ERR_R_DH_LIB);
		return 0;
		}
	EVP_PKEY_assign_DH(pkey, dh);
	return 1;
	}

static int dh_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
	{
	return i2d_DHparams(pkey->pkey.dh, pder);
	}

static int do_dhparam_print(BIO *bp, const DH *x, int indent,
							ASN1_PCTX *ctx)
	{
	unsigned char *m=NULL;
	int reason=ERR_R_BUF_LIB,ret=0;
	size_t buf_len=0, i;

	if (x->p)
		buf_len = (size_t)BN_num_bytes(x->p);
	else
		{
		reason = ERR_R_PASSED_NULL_PARAMETER;
		goto err;
		}
	if (x->g)
		if (buf_len < (i = (size_t)BN_num_bytes(x->g)))
			buf_len = i;
	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		reason=ERR_R_MALLOC_FAILURE;
		goto err;
		}

	BIO_indent(bp, indent, 128);
	if (BIO_printf(bp,"Diffie-Hellman-Parameters: (%d bit)\n",
		BN_num_bits(x->p)) <= 0)
		goto err;
	indent += 4;
	if (!ASN1_bn_print(bp,"prime:",x->p,m,indent)) goto err;
	if (!ASN1_bn_print(bp,"generator:",x->g,m,indent)) goto err;
	if (x->length != 0)
		{
		BIO_indent(bp, indent, 128);
		if (BIO_printf(bp,"recommended-private-length: %d bits\n",
			(int)x->length) <= 0) goto err;
		}
	ret=1;
	if (0)
		{
err:
		DHerr(DH_F_DHPARAMS_PRINT,reason);
		}
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}

static int dh_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *ctx)
	{
	return do_dhparam_print(bp, pkey->pkey.dh, indent, ctx);
	}

int DHparams_print(BIO *bp, const DH *x)
	{
	return do_dhparam_print(bp, x, 4, NULL);
	}

const EVP_PKEY_ASN1_METHOD dh_asn1_meth = 
	{
	EVP_PKEY_DH,
	EVP_PKEY_DH,
	0,

	"DH",
	"OpenSSL PKCS#3 DH method",

	0,
	0,
	0,
	0,

	0,
	0,
	0,

	0,
	0,

	dh_param_decode,
	dh_param_encode,
	0,0,0,
	dh_param_print,

	int_dh_free,
	0
	};

