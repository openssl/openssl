/* crypto/engine/hw_nuron.c */
/* Written by Ben Laurie for the OpenSSL Project, leaning heavily on Geoff
 * Thorpe's Atalla implementation.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include "engine_int.h"
#include <openssl/engine.h>


#ifndef NO_HW
#ifndef NO_HW_NURON

typedef int tfnModExp(BIGNUM *r,BIGNUM *a,const BIGNUM *p,const BIGNUM *m);
static tfnModExp *pfnModExp = NULL;

static DSO *pvDSOHandle = NULL;

static int nuron_init()
	{
	if(pvDSOHandle != NULL)
		{
		ENGINEerr(ENGINE_F_NURON_INIT,ENGINE_R_ALREADY_LOADED);
		return 0;
		}

	pvDSOHandle=DSO_load(NULL,"nuronssl",NULL,
		DSO_FLAG_NAME_TRANSLATION_EXT_ONLY);
	if(!pvDSOHandle)
		{
		ENGINEerr(ENGINE_F_NURON_INIT,ENGINE_R_DSO_NOT_FOUND);
		return 0;
		}

	pfnModExp=(tfnModExp *)DSO_bind_func(pvDSOHandle,"nuron_mod_exp");
	if(!pfnModExp)
		{
		ENGINEerr(ENGINE_F_NURON_INIT,ENGINE_R_DSO_FUNCTION_NOT_FOUND);
		return 0;
		}

	return 1;
	}

static int nuron_finish()
	{
	if(pvDSOHandle == NULL)
		{
		ENGINEerr(ENGINE_F_NURON_FINISH,ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(pvDSOHandle))
		{
		ENGINEerr(ENGINE_F_NURON_FINISH,ENGINE_R_DSO_FAILURE);
		return 0;
		}
	pvDSOHandle=NULL;
	pfnModExp=NULL;
	return 1;
	}

static int nuron_mod_exp(BIGNUM *r,BIGNUM *a,const BIGNUM *p,
			 const BIGNUM *m,BN_CTX *ctx)
	{
	if(!pvDSOHandle)
		{
		ENGINEerr(ENGINE_F_NURON_MOD_EXP,ENGINE_R_NOT_LOADED);
		return 0;
		}
	return pfnModExp(r,a,p,m);
	}

static int nuron_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	return nuron_mod_exp(r0,I,rsa->d,rsa->n,NULL);
	}

/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Atalla acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Atalla system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine atalla dsa1024 rsa1024". */
static int nuron_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
			     BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
			     BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	BIGNUM t;
	int to_return = 0;
 
	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!nuron_mod_exp(rr,a1,p1,m,ctx))
		goto end;
	/* let t = a2 ^ p2 mod m */
	if (!nuron_mod_exp(&t,a2,p2,m,ctx))
		goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr,rr,&t,m,ctx))
		goto end;
	to_return = 1;
end:
	BN_free(&t);
	return to_return;
	}


static int nuron_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
			     const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
			     BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int nuron_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}

/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int nuron_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}

static RSA_METHOD nuron_rsa =
	{
	"Nuron RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	nuron_rsa_mod_exp,
	nuron_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};

static DSA_METHOD nuron_dsa =
	{
	"Nuron DSA method",
	NULL, /* dsa_do_sign */
	NULL, /* dsa_sign_setup */
	NULL, /* dsa_do_verify */
	nuron_dsa_mod_exp, /* dsa_mod_exp */
	nuron_mod_exp_dsa, /* bn_mod_exp */
	NULL, /* init */
	NULL, /* finish */
	0, /* flags */
	NULL /* app_data */
	};

static DH_METHOD nuron_dh =
	{
	"Nuron DH method",
	NULL,
	NULL,
	nuron_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};

static ENGINE engine_nuron =
	{
	"nuron",
	"Nuron hardware engine support",
	&nuron_rsa,
	&nuron_dsa,
	&nuron_dh,
	NULL,
	nuron_mod_exp,
	NULL,
	nuron_init,
	nuron_finish,
	NULL, /* no ctrl() */
	NULL, /* no load_privkey() */
	NULL, /* no load_pubkey() */
	0, /* no flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
	};

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_nuron()
	{
	RSA_METHOD *meth1;
	DSA_METHOD *meth2;
	DH_METHOD *meth3;

	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the nuron-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1=RSA_PKCS1_SSLeay();
	nuron_rsa.rsa_pub_enc=meth1->rsa_pub_enc;
	nuron_rsa.rsa_pub_dec=meth1->rsa_pub_dec;
	nuron_rsa.rsa_priv_enc=meth1->rsa_priv_enc;
	nuron_rsa.rsa_priv_dec=meth1->rsa_priv_dec;

	/* Use the DSA_OpenSSL() method and just hook the mod_exp-ish
	 * bits. */
	meth2=DSA_OpenSSL();
	nuron_dsa.dsa_do_sign=meth2->dsa_do_sign;
	nuron_dsa.dsa_sign_setup=meth2->dsa_sign_setup;
	nuron_dsa.dsa_do_verify=meth2->dsa_do_verify;

	/* Much the same for Diffie-Hellman */
	meth3=DH_OpenSSL();
	nuron_dh.generate_key=meth3->generate_key;
	nuron_dh.compute_key=meth3->compute_key;
	return &engine_nuron;
	}

#endif /* !NO_HW_NURON */
#endif /* !NO_HW */
