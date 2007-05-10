/* bio_pk7.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project.
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

#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>

#include <memory.h>
#include <stdio.h>

/* Highly experiemental PKCS#7 BIO support routines */

/* The usage is quite simple, initialize a PKCS7 structure,
 * get a BIO from it then any data written through the BIO
 * will end up translated to PKCS#7 format on the fly.
 * The data is streamed out and does *not* need to be
 * all held in memory at once.
 *
 * When the BIO is flushed the output is finalized and any
 * signatures etc written out.
 *
 * The BIO is a 'proper' BIO and can handle non blocking I/O
 * correctly.
 *
 * The usage is simple. The implementation is *not*...
 */

/* BIO support data stored in the ASN1 BIO ex_arg */

typedef struct pkcs7_aux_st
	{
	/* PKCS7 structure this BIO refers to */
	PKCS7 *p7;
	/* Top of the BIO chain */
	BIO *p7bio;
	/* Output BIO */
	BIO *out;
	/* Boundary where content is inserted */
	unsigned char **boundary;
	/* DER buffer start */
	unsigned char *derbuf;
	} PKCS7_SUPPORT;

static int pkcs7_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg);
static int pkcs7_prefix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg);
static int pkcs7_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg);
static int pkcs7_suffix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg);

BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7) 
	{
	PKCS7_SUPPORT *p7aux = NULL;
	BIO *p7bio = NULL;
	BIO *asn_bio = NULL;
	unsigned char **boundary;
	p7aux = OPENSSL_malloc(sizeof(PKCS7_SUPPORT));
	asn_bio = BIO_new(BIO_f_asn1());

	/* ASN1 bio needs to be next to output BIO */

	out = BIO_push(asn_bio, out);

	if (!p7aux || !asn_bio || !out)
		goto err;

	BIO_asn1_set_prefix(asn_bio, pkcs7_prefix, pkcs7_prefix_free);
	BIO_asn1_set_suffix(asn_bio, pkcs7_suffix, pkcs7_suffix_free);

	/* Now initialize BIO for PKCS#7 output */

	p7bio = PKCS7_dataInit(p7, out);
	if (!p7bio || !PKCS7_stream(&boundary, p7))
		goto err;

	p7aux->p7 = p7;
	p7aux->p7bio = p7bio;
	p7aux->boundary = boundary;
	p7aux->out = out;

	BIO_ctrl(asn_bio, BIO_C_SET_EX_ARG, 0, p7aux);

	return p7bio;

	err:
	if (p7bio)
		BIO_free(p7bio);
	if (asn_bio)
		BIO_free(asn_bio);
	if (p7aux)
		OPENSSL_free(p7aux);
	return NULL;
	}

static int pkcs7_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
	{
	PKCS7_SUPPORT *p7aux;
	unsigned char *p;
	int derlen;

	if (!parg)
		return 0;

	p7aux = *(PKCS7_SUPPORT **)parg;

	derlen = i2d_PKCS7_NDEF(p7aux->p7, NULL);
	p = OPENSSL_malloc(derlen);
	p7aux->derbuf = p;
	*pbuf = p;
	i2d_PKCS7_NDEF(p7aux->p7, &p);

	if (!*p7aux->boundary)
		return 0;

	*plen = *p7aux->boundary - *pbuf;

	return 1;
	}

static int pkcs7_prefix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg)
	{
	PKCS7_SUPPORT *p7aux;

	if (!parg)
		return 0;

	p7aux = *(PKCS7_SUPPORT **)parg;

	if (p7aux->derbuf)
		OPENSSL_free(p7aux->derbuf);

	p7aux->derbuf = NULL;
	*pbuf = NULL;
	*plen = 0;
	return 1;
	}

static int pkcs7_suffix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg)
	{
	PKCS7_SUPPORT **pp7aux = (PKCS7_SUPPORT **)parg;
	if (!pkcs7_prefix_free(b, pbuf, plen, parg))
		return 0;
	OPENSSL_free(*pp7aux);
	*pp7aux = NULL;
	return 1;
	}

static int pkcs7_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
	{
	PKCS7_SUPPORT *p7aux;
	unsigned char *p;
	int derlen;

	if (!parg)
		return 0;

	p7aux = *(PKCS7_SUPPORT **)parg;

	/* Finalize structures */
	PKCS7_dataFinal(p7aux->p7, p7aux->p7bio);

	derlen = i2d_PKCS7_NDEF(p7aux->p7, NULL);
	p = OPENSSL_malloc(derlen);
	p7aux->derbuf = p;
	i2d_PKCS7_NDEF(p7aux->p7, &p);
	if (!*p7aux->boundary)
		return 0;
	*pbuf = *p7aux->boundary;
	*plen = derlen - (*p7aux->boundary - p7aux->derbuf);

	return 1;
	}
	

