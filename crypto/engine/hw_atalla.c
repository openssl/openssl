/* crypto/engine/hw_atalla.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#ifndef NO_HW_ATALLA

#ifdef FLAT_INC
#include "atalla.h"
#else
#include "vendor_defns/atalla.h"
#endif

static int atalla_init(void);
static int atalla_finish(void);

/* BIGNUM stuff */
static int atalla_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);

/* RSA stuff */
static int atalla_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa);
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int atalla_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* DSA stuff */
static int atalla_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
		BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
		BN_CTX *ctx, BN_MONT_CTX *in_mont);
static int atalla_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
		const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
		BN_MONT_CTX *m_ctx);

/* DH stuff */
/* This function is alised to mod_exp (with the DH and mont dropped). */
static int atalla_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);


/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD atalla_rsa =
	{
	"Atalla RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	atalla_rsa_mod_exp,
	atalla_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};

/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD atalla_dsa =
	{
	"Atalla DSA method",
	NULL, /* dsa_do_sign */
	NULL, /* dsa_sign_setup */
	NULL, /* dsa_do_verify */
	atalla_dsa_mod_exp, /* dsa_mod_exp */
	atalla_mod_exp_dsa, /* bn_mod_exp */
	NULL, /* init */
	NULL, /* finish */
	0, /* flags */
	NULL /* app_data */
	};

/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD atalla_dh =
	{
	"Atalla DH method",
	NULL,
	NULL,
	atalla_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};

/* Our ENGINE structure. */
static ENGINE engine_atalla =
        {
	"atalla",
	"Atalla hardware engine support",
	&atalla_rsa,
	&atalla_dsa,
	&atalla_dh,
	NULL,
	atalla_mod_exp,
	NULL,
	atalla_init,
	atalla_finish,
	NULL, /* no ctrl() */
	NULL, /* no load_privkey() */
	NULL, /* no load_pubkey() */
	0, /* no flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
        };

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_atalla()
	{
	RSA_METHOD *meth1;
	DSA_METHOD *meth2;
	DH_METHOD *meth3;

	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the atalla-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1 = RSA_PKCS1_SSLeay();
	atalla_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
	atalla_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
	atalla_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
	atalla_rsa.rsa_priv_dec = meth1->rsa_priv_dec;

	/* Use the DSA_OpenSSL() method and just hook the mod_exp-ish
	 * bits. */
	meth2 = DSA_OpenSSL();
	atalla_dsa.dsa_do_sign = meth2->dsa_do_sign;
	atalla_dsa.dsa_sign_setup = meth2->dsa_sign_setup;
	atalla_dsa.dsa_do_verify = meth2->dsa_do_verify;

	/* Much the same for Diffie-Hellman */
	meth3 = DH_OpenSSL();
	atalla_dh.generate_key = meth3->generate_key;
	atalla_dh.compute_key = meth3->compute_key;
	return &engine_atalla;
	}

/* This is a process-global DSO handle used for loading and unloading
 * the Atalla library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
static DSO *atalla_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
static tfnASI_GetHardwareConfig *p_Atalla_GetHardwareConfig = NULL;
static tfnASI_RSAPrivateKeyOpFn *p_Atalla_RSAPrivateKeyOpFn = NULL;
static tfnASI_GetPerformanceStatistics *p_Atalla_GetPerformanceStatistics = NULL;

/* (de)initialisation functions. */
static int atalla_init()
	{
	tfnASI_GetHardwareConfig *p1;
	tfnASI_RSAPrivateKeyOpFn *p2;
	tfnASI_GetPerformanceStatistics *p3;
	/* Not sure of the origin of this magic value, but Ben's code had it
	 * and it seemed to have been working for a few people. :-) */
	unsigned int config_buf[1024];

	if(atalla_dso != NULL)
		{
		ENGINEerr(ENGINE_F_ATALLA_INIT,ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* Attempt to load libatasi.so/atasi.dll/whatever. Needs to be
	 * changed unfortunately because the Atalla drivers don't have
	 * standard library names that can be platform-translated well. */
	/* TODO: Work out how to actually map to the names the Atalla
	 * drivers really use - for now a symbollic link needs to be
	 * created on the host system from libatasi.so to atasi.so on
	 * unix variants. */
	atalla_dso = DSO_load(NULL, ATALLA_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION);
	if(atalla_dso == NULL)
		{
		ENGINEerr(ENGINE_F_ATALLA_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	if(!(p1 = (tfnASI_GetHardwareConfig *)DSO_bind_func(
				atalla_dso, ATALLA_F1)) ||
			!(p2 = (tfnASI_RSAPrivateKeyOpFn *)DSO_bind_func(
				atalla_dso, ATALLA_F2)) ||
			!(p3 = (tfnASI_GetPerformanceStatistics *)DSO_bind_func(
				atalla_dso, ATALLA_F3)))
		{
		ENGINEerr(ENGINE_F_ATALLA_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	/* Copy the pointers */
	p_Atalla_GetHardwareConfig = p1;
	p_Atalla_RSAPrivateKeyOpFn = p2;
	p_Atalla_GetPerformanceStatistics = p3;
	/* Perform a basic test to see if there's actually any unit
	 * running. */
	if(p1(0L, config_buf) != 0)
		{
		ENGINEerr(ENGINE_F_ATALLA_INIT,ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	/* Everything's fine. */
	return 1;
err:
	if(atalla_dso)
		DSO_free(atalla_dso);
	p_Atalla_GetHardwareConfig = NULL;
	p_Atalla_RSAPrivateKeyOpFn = NULL;
	p_Atalla_GetPerformanceStatistics = NULL;
	return 0;
	}

static int atalla_finish()
	{
	if(atalla_dso == NULL)
		{
		ENGINEerr(ENGINE_F_ATALLA_FINISH,ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(atalla_dso))
		{
		ENGINEerr(ENGINE_F_ATALLA_FINISH,ENGINE_R_DSO_FAILURE);
		return 0;
		}
	atalla_dso = NULL;
	p_Atalla_GetHardwareConfig = NULL;
	p_Atalla_RSAPrivateKeyOpFn = NULL;
	p_Atalla_GetPerformanceStatistics = NULL;
	return 1;
	}

static int atalla_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx)
	{
	/* I need somewhere to store temporary serialised values for
	 * use with the Atalla API calls. A neat cheat - I'll use
	 * BIGNUMs from the BN_CTX but access their arrays directly as
	 * byte arrays <grin>. This way I don't have to clean anything
	 * up. */
	BIGNUM *modulus;
	BIGNUM *exponent;
	BIGNUM *argument;
	BIGNUM *result;
	RSAPrivateKey keydata;
	int to_return, numbytes;

	modulus = exponent = argument = result = NULL;
	to_return = 0; /* expect failure */

	if(!atalla_dso)
	{
		ENGINEerr(ENGINE_F_ATALLA_MOD_EXP,ENGINE_R_NOT_LOADED);
		goto err;
	}
	/* Prepare the params */
	modulus = BN_CTX_get(ctx);
	exponent = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!modulus || !exponent || !argument || !result)
	{
		ENGINEerr(ENGINE_F_ATALLA_MOD_EXP,ENGINE_R_BN_CTX_FULL);
		goto err;
	}
	if(!bn_wexpand(modulus, m->top) || !bn_wexpand(exponent, m->top) ||
	   !bn_wexpand(argument, m->top) || !bn_wexpand(result, m->top))
	{
		ENGINEerr(ENGINE_F_ATALLA_MOD_EXP,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	}
	/* Prepare the key-data */
	memset(&keydata, 0,sizeof keydata);
	numbytes = BN_num_bytes(m);
	memset(exponent->d, 0, numbytes);
	memset(modulus->d, 0, numbytes);
	BN_bn2bin(p, (unsigned char *)exponent->d + numbytes - BN_num_bytes(p));
	BN_bn2bin(m, (unsigned char *)modulus->d + numbytes - BN_num_bytes(m));
	keydata.privateExponent.data = (unsigned char *)exponent->d;
	keydata.privateExponent.len = numbytes;
	keydata.modulus.data = (unsigned char *)modulus->d;
	keydata.modulus.len = numbytes;
	/* Prepare the argument */
	memset(argument->d, 0, numbytes);
	memset(result->d, 0, numbytes);
	BN_bn2bin(a, (unsigned char *)argument->d + numbytes - BN_num_bytes(a));
	/* Perform the operation */
	if(p_Atalla_RSAPrivateKeyOpFn(&keydata, (unsigned char *)result->d,
			(unsigned char *)argument->d,
			keydata.modulus.len) != 0)
	{
		ENGINEerr(ENGINE_F_ATALLA_MOD_EXP,ENGINE_R_REQUEST_FAILED);
		goto err;
	}
	/* Convert the response */
	BN_bin2bn((unsigned char *)result->d, numbytes, r);
	to_return = 1;
err:
	if(modulus) ctx->tos--;
	if(exponent) ctx->tos--;
	if(argument) ctx->tos--;
	if(result) ctx->tos--;
	return to_return;
	}

static int atalla_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	BN_CTX *ctx = NULL;
	int to_return = 0;

	if(!atalla_dso)
	{
		ENGINEerr(ENGINE_F_ATALLA_RSA_MOD_EXP,ENGINE_R_NOT_LOADED);
		goto err;
	}
	if((ctx = BN_CTX_new()) == NULL)
		goto err;
	if(!rsa->d || !rsa->n)
		{
		ENGINEerr(ENGINE_F_ATALLA_RSA_MOD_EXP,ENGINE_R_MISSING_KEY_COMPONENTS);
		goto err;
		}
	to_return = atalla_mod_exp(r0, I, rsa->d, rsa->n, ctx);
err:
	if(ctx)
		BN_CTX_free(ctx);
	return to_return;
	}

/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Atalla acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Atalla system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine atalla dsa1024 rsa1024". */
static int atalla_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
		BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
		BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	BIGNUM t;
	int to_return = 0;
 
	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!atalla_mod_exp(rr,a1,p1,m,ctx)) goto end;
	/* let t = a2 ^ p2 mod m */
	if (!atalla_mod_exp(&t,a2,p2,m,ctx)) goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr,rr,&t,m,ctx)) goto end;
	to_return = 1;
end:
	BN_free(&t);
	return to_return;
	}


static int atalla_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
		const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
		BN_MONT_CTX *m_ctx)
	{
	return atalla_mod_exp(r, a, p, m, ctx);
	}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int atalla_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return atalla_mod_exp(r, a, p, m, ctx);
	}

/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int atalla_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return atalla_mod_exp(r, a, p, m, ctx);
	}

#endif /* !NO_HW_ATALLA */
#endif /* !NO_HW */
