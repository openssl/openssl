/* crypto/ecdh/ecdhtest.c */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef OPENSSL_SYS_WINDOWS
#include "../bio/bss_file.c" 
#endif
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_ECDH
int main(int argc, char *argv[])
{
    printf("No ECDH support\n");
    return(0);
}
#else
#include <openssl/ecdh.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif

#if 0
static void MS_CALLBACK cb(int p, int n, void *arg);
#endif

#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#include "bss_file.c"
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int test_ecdh_curve(int , char *, BN_CTX *, BIO *);

int test_ecdh_curve(int nid, char *text, BN_CTX *ctx, BIO *out)
	{
	EC_KEY *a=NULL;
	EC_KEY *b=NULL;
	BIGNUM *x=NULL, *y=NULL;
	char buf[12];
	unsigned char *abuf=NULL,*bbuf=NULL;
	int i,alen,blen,aout,bout,ret=0;

	if ((a=EC_KEY_new()) == NULL) goto err;
	if ((a->group=EC_GROUP_new_by_nid(nid)) == NULL) goto err;

	if ((b=EC_KEY_new()) == NULL) goto err;
	b->group = a->group;

	if ((x=BN_new()) == NULL) goto err;
	if ((y=BN_new()) == NULL) goto err;

	BIO_puts(out,"Testing key generation with ");
	BIO_puts(out,text);
	BIO_puts(out,"\n");

	if (!EC_KEY_generate_key(a)) goto err;
	BIO_puts(out,"  pri 1=");
	BN_print(out,a->priv_key);
	BIO_puts(out,"\n  pub 1=");
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(a->group)) == NID_X9_62_prime_field) 
		{
		if (!EC_POINT_get_affine_coordinates_GFp(a->group, a->pub_key, x, y, ctx)) goto err;
		}
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(a->group, a->pub_key, x, y, ctx)) goto err;
		}
	BN_print(out,x);
	BIO_puts(out,",");
	BN_print(out,y);
	BIO_puts(out,"\n");

	if (!EC_KEY_generate_key(b)) goto err;
	BIO_puts(out,"  pri 2=");
	BN_print(out,b->priv_key);
	BIO_puts(out,"\n  pub 2=");
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(b->group)) == NID_X9_62_prime_field) 
		{
		if (!EC_POINT_get_affine_coordinates_GFp(b->group, b->pub_key, x, y, ctx)) goto err;
		}
	else
		{
		if (!EC_POINT_get_affine_coordinates_GF2m(a->group, b->pub_key, x, y, ctx)) goto err;
		}
	BN_print(out,x);
	BIO_puts(out,",");
	BN_print(out,y);
	BIO_puts(out,"\n");

	alen=ECDH_size(a);
	abuf=(unsigned char *)OPENSSL_malloc(alen);
	aout=ECDH_compute_key(abuf,b->pub_key,a);

	BIO_puts(out,"  key1 =");
	for (i=0; i<aout; i++)
		{
		sprintf(buf,"%02X",abuf[i]);
		BIO_puts(out,buf);
		}
	BIO_puts(out,"\n");

	blen=ECDH_size(b);
	bbuf=(unsigned char *)OPENSSL_malloc(blen);
	bout=ECDH_compute_key(bbuf,a->pub_key,b);

	BIO_puts(out,"  key2 =");
	for (i=0; i<bout; i++)
		{
		sprintf(buf,"%02X",bbuf[i]);
		BIO_puts(out,buf);
		}
	BIO_puts(out,"\n");
	if ((aout < 4) || (bout != aout) || (memcmp(abuf,bbuf,aout) != 0))
		{
		fprintf(stderr,"Error in ECDH routines\n");
		ret=0;
		}
	else
		ret=1;
err:
	ERR_print_errors_fp(stderr);

	if (abuf != NULL) OPENSSL_free(abuf);
	if (bbuf != NULL) OPENSSL_free(bbuf);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (a->group) EC_GROUP_free(a->group);
	a->group = b->group = NULL;
	if (b) EC_KEY_free(b);
	if (a) EC_KEY_free(a);
	return(ret);
	}

int main(int argc, char *argv[])
	{
	BN_CTX *ctx=NULL;
	int ret=1;
	BIO *out;

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif

	RAND_seed(rnd_seed, sizeof rnd_seed);

	out=BIO_new(BIO_s_file());
	if (out == NULL) exit(1);
	BIO_set_fp(out,stdout,BIO_NOCLOSE);

	if ((ctx=BN_CTX_new()) == NULL) goto err;

	/* NIST PRIME CURVES TESTS */
	if (!test_ecdh_curve(NID_X9_62_prime192v1, "NIST Prime-Curve P-192", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_secp224r1, "NIST Prime-Curve P-224", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_X9_62_prime256v1, "NIST Prime-Curve P-256", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_secp384r1, "NIST Prime-Curve P-384", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_secp521r1, "NIST Prime-Curve P-521", ctx, out)) goto err;
	/* NIST BINARY CURVES TESTS */
	if (!test_ecdh_curve(NID_sect163k1, "NIST Binary-Curve K-163", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect163r2, "NIST Binary-Curve B-163", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect233k1, "NIST Binary-Curve K-233", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect233r1, "NIST Binary-Curve B-233", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect283k1, "NIST Binary-Curve K-283", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect283r1, "NIST Binary-Curve B-283", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect409k1, "NIST Binary-Curve K-409", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect409r1, "NIST Binary-Curve B-409", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect571k1, "NIST Binary-Curve K-571", ctx, out)) goto err;
	if (!test_ecdh_curve(NID_sect571r1, "NIST Binary-Curve B-571", ctx, out)) goto err;

	ret = 0;

err:
	ERR_print_errors_fp(stderr);
	if (ctx) BN_CTX_free(ctx);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
	exit(ret);
	return(ret);
	}

#if 0
static void MS_CALLBACK cb(int p, int n, void *arg)
	{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write((BIO *)arg,&c,1);
	(void)BIO_flush((BIO *)arg);
#ifdef LINT
	p=n;
#endif
	}
#endif
#endif
