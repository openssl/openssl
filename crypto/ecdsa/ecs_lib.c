/* crypto/ecdsa/ecs_lib.c */
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
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

#include "cryptlib.h"
#include "ecdsa.h"
#include <openssl/engine.h>

const char *ECDSA_version="ECDSA" OPENSSL_VERSION_PTEXT;

static const ECDSA_METHOD *default_ECDSA_method = NULL;

void ECDSA_set_default_method(const ECDSA_METHOD *meth)
{
	default_ECDSA_method = meth;
}

const ECDSA_METHOD *ECDSA_get_default_method(void)
{
	if(!default_ECDSA_method) 
		default_ECDSA_method = ECDSA_OpenSSL();
	return default_ECDSA_method;
}

ECDSA *ECDSA_new(void)
{
	return ECDSA_new_method(NULL);
}

int ECDSA_set_method(ECDSA *ecdsa, const ECDSA_METHOD *meth)
{
        const ECDSA_METHOD *mtmp;
        mtmp = ecdsa->meth;
        if (mtmp->finish) mtmp->finish(ecdsa);
	if (ecdsa->engine)
	{
		ENGINE_finish(ecdsa->engine);
		ecdsa->engine = NULL;
	}
        ecdsa->meth = meth;
        if (meth->init) meth->init(ecdsa);
        return 1;
}

ECDSA *ECDSA_new_method(ENGINE *engine)
{
	ECDSA *ret;

	ret=(ECDSA *)OPENSSL_malloc(sizeof(ECDSA));
	if (ret == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
	}

	ret->meth = ECDSA_get_default_method();
	ret->engine = engine;
	if (!ret->engine)
		ret->engine = ENGINE_get_default_ECDSA();
	if (ret->engine)
	{
		ret->meth = ENGINE_get_ECDSA(ret->engine);
		if (!ret->meth)
		{
			ECDSAerr(ECDSA_R_ECDSA_F_ECDSA_NEW, ERR_R_ENGINE_LIB);
			ENGINE_finish(ret->engine);
			OPENSSL_free(ret);
			return NULL;
		}
	}

	ret->version = 1;
	ret->conversion_form = ECDSA_get_default_conversion_form();
	ret->group = NULL;

	ret->pub_key = NULL;
	ret->priv_key = NULL;

	ret->kinv = NULL;
	ret->r = NULL;

	ret->references = 1;
	ret->flags = ret->meth->flags;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDSA, ret, &ret->ex_data);
	if ((ret->meth->init != NULL) && !ret->meth->init(ret))
	{
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDSA, ret, &ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
	}
	
	return(ret);
}

void ECDSA_free(ECDSA *r)
{
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_ECDSA);
#ifdef REF_PRINT
	REF_PRINT("ECDSA",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
	{
		fprintf(stderr,"ECDSA_free, bad reference count\n");
		abort();
	}
#endif

	if (r->meth->finish)
		r->meth->finish(r);
	if (r->engine)
		ENGINE_finish(r->engine);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDSA, r, &r->ex_data);

	if (r->group    != NULL) EC_GROUP_free(r->group);
	if (r->pub_key  != NULL) EC_POINT_free(r->pub_key);
	if (r->priv_key != NULL) BN_clear_free(r->priv_key);
	if (r->kinv != NULL) BN_clear_free(r->kinv);
	if (r->r    != NULL) BN_clear_free(r->r);
	OPENSSL_free(r);
}

int ECDSA_size(const ECDSA *r)
{
	int ret,i;
	ASN1_INTEGER bs;
	BIGNUM	*order=NULL;
	unsigned char buf[4];

	if (r == NULL || r->group == NULL)
		return 0;
	if ((order = BN_new()) == NULL) return 0;
	if (!EC_GROUP_get_order(r->group,order,NULL))
	{
		BN_clear_free(order);
		return 0;
	} 
	i=BN_num_bits(order);
	bs.length=(i+7)/8;
	bs.data=buf;
	bs.type=V_ASN1_INTEGER;
	/* If the top bit is set the asn1 encoding is 1 larger. */
	buf[0]=0xff;	

	i=i2d_ASN1_INTEGER(&bs,NULL);
	i+=i; /* r and s */
	ret=ASN1_object_size(1,i,V_ASN1_SEQUENCE);
	BN_clear_free(order);
	return(ret);
}

int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ECDSA, argl, argp,
				new_func, dup_func, free_func);
}

int ECDSA_set_ex_data(ECDSA *d, int idx, void *arg)
{
	return(CRYPTO_set_ex_data(&d->ex_data,idx,arg));
}

void *ECDSA_get_ex_data(ECDSA *d, int idx)
{
	return(CRYPTO_get_ex_data(&d->ex_data,idx));
}

int ECDSA_up_ref(ECDSA *ecdsa)
{
	int i = CRYPTO_add(&ecdsa->references, 1, CRYPTO_LOCK_ECDSA);
#ifdef REF_PRINT
	REF_PRINT("ECDSA",r);
#endif	
#ifdef REF_CHECK
	if (i < 2)
	{
	        fprintf(stderr, "ECDSA_up_ref, bad reference count\n");
                abort();
        }
#endif
        return ((i > 1) ? 1 : 0);
}
        
void	ECDSA_set_conversion_form(ECDSA *ecdsa, const point_conversion_form_t form)
{
	if (ecdsa) ecdsa->conversion_form = form;
}

point_conversion_form_t ECDSA_get_conversion_form(const ECDSA *ecdsa)
{
	return ecdsa ? ecdsa->conversion_form : 0;
}

static point_conversion_form_t default_conversion_form = POINT_CONVERSION_UNCOMPRESSED;

void	ECDSA_set_default_conversion_form(const point_conversion_form_t form)
{
	default_conversion_form = form;
}

point_conversion_form_t ECDSA_get_default_conversion_form(void)
{
	return default_conversion_form;
}
