/* crypto/engine/hw_cswift.c */
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
#ifndef NO_HW_CSWIFT

/* Attribution notice: Rainbow have generously allowed me to reproduce
 * the necessary definitions here from their API. This means the support
 * can build independently of whether application builders have the
 * API or hardware. This will allow developers to easily produce software
 * that has latent hardware support for any users that have accelerators
 * installed, without the developers themselves needing anything extra.
 *
 * I have only clipped the parts from the CryptoSwift header files that
 * are (or seem) relevant to the CryptoSwift support code. This is
 * simply to keep the file sizes reasonable.
 * [Geoff]
 */
#ifdef FLAT_INC
#include "cswift.h"
#else
#include "vendor_defns/cswift.h"
#endif

static int cswift_init(void);
static int cswift_finish(void);

/* BIGNUM stuff */
static int cswift_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);
static int cswift_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

/* RSA stuff */
static int cswift_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa);
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int cswift_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* DSA stuff */
static DSA_SIG *cswift_dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int cswift_dsa_verify(const unsigned char *dgst, int dgst_len,
				DSA_SIG *sig, DSA *dsa);

/* DH stuff */
/* This function is alised to mod_exp (with the DH and mont dropped). */
static int cswift_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);


/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD cswift_rsa =
	{
	"CryptoSwift RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	cswift_rsa_mod_exp,
	cswift_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};

/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD cswift_dsa =
	{
	"CryptoSwift DSA method",
	cswift_dsa_sign,
	NULL, /* dsa_sign_setup */
	cswift_dsa_verify,
	NULL, /* dsa_mod_exp */
	NULL, /* bn_mod_exp */
	NULL, /* init */
	NULL, /* finish */
	0, /* flags */
	NULL /* app_data */
	};

/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD cswift_dh =
	{
	"CryptoSwift DH method",
	NULL,
	NULL,
	cswift_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};

/* Our ENGINE structure. */
static ENGINE engine_cswift =
        {
	"cswift",
	"CryptoSwift hardware engine support",
	&cswift_rsa,
	&cswift_dsa,
	&cswift_dh,
	NULL,
	cswift_mod_exp,
	cswift_mod_exp_crt,
	cswift_init,
	cswift_finish,
	NULL, /* no ctrl() */
	NULL, /* no load_privkey() */
	NULL, /* no load_pubkey() */
	0, /* no flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
        };

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_cswift()
	{
	RSA_METHOD *meth1;
	DH_METHOD *meth2;

	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the cswift-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1 = RSA_PKCS1_SSLeay();
	cswift_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
	cswift_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
	cswift_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
	cswift_rsa.rsa_priv_dec = meth1->rsa_priv_dec;

	/* Much the same for Diffie-Hellman */
	meth2 = DH_OpenSSL();
	cswift_dh.generate_key = meth2->generate_key;
	cswift_dh.compute_key = meth2->compute_key;
	return &engine_cswift;
	}

/* This is a process-global DSO handle used for loading and unloading
 * the CryptoSwift library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
static DSO *cswift_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
t_swAcquireAccContext *p_CSwift_AcquireAccContext = NULL;
t_swAttachKeyParam *p_CSwift_AttachKeyParam = NULL;
t_swSimpleRequest *p_CSwift_SimpleRequest = NULL;
t_swReleaseAccContext *p_CSwift_ReleaseAccContext = NULL;

/* Used in the DSO operations. */
static const char *CSWIFT_LIBNAME = "swift";
static const char *CSWIFT_F1 = "swAcquireAccContext";
static const char *CSWIFT_F2 = "swAttachKeyParam";
static const char *CSWIFT_F3 = "swSimpleRequest";
static const char *CSWIFT_F4 = "swReleaseAccContext";


/* CryptoSwift library functions and mechanics - these are used by the
 * higher-level functions further down. NB: As and where there's no
 * error checking, take a look lower down where these functions are
 * called, the checking and error handling is probably down there. */

/* utility function to obtain a context */
static int get_context(SW_CONTEXT_HANDLE *hac)
	{
        SW_STATUS status;
 
        status = p_CSwift_AcquireAccContext(hac);
        if(status != SW_OK)
                return 0;
        return 1;
	}
 
/* similarly to release one. */
static void release_context(SW_CONTEXT_HANDLE hac)
	{
        p_CSwift_ReleaseAccContext(hac);
	}

/* (de)initialisation functions. */
static int cswift_init()
	{
        SW_CONTEXT_HANDLE hac;
        t_swAcquireAccContext *p1;
        t_swAttachKeyParam *p2;
        t_swSimpleRequest *p3;
        t_swReleaseAccContext *p4;

	if(cswift_dso != NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* Attempt to load libswift.so/swift.dll/whatever. */
	cswift_dso = DSO_load(NULL, CSWIFT_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION);
	if(cswift_dso == NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	if(!(p1 = (t_swAcquireAccContext *)
				DSO_bind_func(cswift_dso, CSWIFT_F1)) ||
			!(p2 = (t_swAttachKeyParam *)
				DSO_bind_func(cswift_dso, CSWIFT_F2)) ||
			!(p3 = (t_swSimpleRequest *)
				DSO_bind_func(cswift_dso, CSWIFT_F3)) ||
			!(p4 = (t_swReleaseAccContext *)
				DSO_bind_func(cswift_dso, CSWIFT_F4)))
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	/* Copy the pointers */
	p_CSwift_AcquireAccContext = p1;
	p_CSwift_AttachKeyParam = p2;
	p_CSwift_SimpleRequest = p3;
	p_CSwift_ReleaseAccContext = p4;
	/* Try and get a context - if not, we may have a DSO but no
	 * accelerator! */
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	release_context(hac);
	/* Everything's fine. */
	return 1;
err:
	if(cswift_dso)
		DSO_free(cswift_dso);
	p_CSwift_AcquireAccContext = NULL;
	p_CSwift_AttachKeyParam = NULL;
	p_CSwift_SimpleRequest = NULL;
	p_CSwift_ReleaseAccContext = NULL;
	return 0;
	}

static int cswift_finish()
	{
	if(cswift_dso == NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_FINISH,ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(cswift_dso))
		{
		ENGINEerr(ENGINE_F_CSWIFT_FINISH,ENGINE_R_DSO_FAILURE);
		return 0;
		}
	cswift_dso = NULL;
	p_CSwift_AcquireAccContext = NULL;
	p_CSwift_AttachKeyParam = NULL;
	p_CSwift_SimpleRequest = NULL;
	p_CSwift_ReleaseAccContext = NULL;
	return 1;
	}

/* Un petit mod_exp */
static int cswift_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx)
	{
	/* I need somewhere to store temporary serialised values for
	 * use with the CryptoSwift API calls. A neat cheat - I'll use
	 * BIGNUMs from the BN_CTX but access their arrays directly as
	 * byte arrays <grin>. This way I don't have to clean anything
	 * up. */
	BIGNUM *modulus;
	BIGNUM *exponent;
	BIGNUM *argument;
	BIGNUM *result;
	SW_STATUS sw_status;
	SW_LARGENUMBER arg, res;
	SW_PARAM sw_param;
	SW_CONTEXT_HANDLE hac;
	int to_return, acquired;
 
	modulus = exponent = argument = result = NULL;
	to_return = 0; /* expect failure */
	acquired = 0;
 
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	modulus = BN_CTX_get(ctx);
	exponent = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!modulus || !exponent || !argument || !result)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(modulus, m->top) || !bn_wexpand(exponent, p->top) ||
		!bn_wexpand(argument, a->top) || !bn_wexpand(result, m->top))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_EXP;
	sw_param.up.exp.modulus.nbytes = BN_bn2bin(m,
		(unsigned char *)modulus->d);
	sw_param.up.exp.modulus.value = (unsigned char *)modulus->d;
	sw_param.up.exp.exponent.nbytes = BN_bn2bin(p,
		(unsigned char *)exponent->d);
	sw_param.up.exp.exponent.value = (unsigned char *)exponent->d;
	/* Attach the key params */
	sw_status = p_CSwift_AttachKeyParam(hac, &sw_param);
	switch(sw_status)
		{
	case SW_OK:
		break;
	case SW_ERR_INPUT_SIZE:
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,
			ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
		goto err;
	default:
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		}
		goto err;
		}
	/* Prepare the argument and response */
	arg.nbytes = BN_bn2bin(a, (unsigned char *)argument->d);
	arg.value = (unsigned char *)argument->d;
	res.nbytes = BN_num_bytes(m);
	memset(result->d, 0, res.nbytes);
	res.value = (unsigned char *)result->d;
	/* Perform the operation */
	if((sw_status = p_CSwift_SimpleRequest(hac, SW_CMD_MODEXP, &arg, 1,
		&res, 1)) != SW_OK)
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		goto err;
		}
	/* Convert the response */
	BN_bin2bn((unsigned char *)result->d, res.nbytes, r);
	to_return = 1;
err:
	if(acquired)
		release_context(hac);
	if(modulus) ctx->tos--;
	if(exponent) ctx->tos--;
	if(argument) ctx->tos--;
	if(result) ctx->tos--;
	return to_return;
	}

/* Un petit mod_exp chinois */
static int cswift_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *q, const BIGNUM *dmp1,
			const BIGNUM *dmq1, const BIGNUM *iqmp, BN_CTX *ctx)
	{
	SW_STATUS sw_status;
	SW_LARGENUMBER arg, res;
	SW_PARAM sw_param;
	SW_CONTEXT_HANDLE hac;
	BIGNUM *rsa_p = NULL;
	BIGNUM *rsa_q = NULL;
	BIGNUM *rsa_dmp1 = NULL;
	BIGNUM *rsa_dmq1 = NULL;
	BIGNUM *rsa_iqmp = NULL;
	BIGNUM *argument = NULL;
	BIGNUM *result = NULL;
	int to_return = 0; /* expect failure */
	int acquired = 0;
 
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	rsa_p = BN_CTX_get(ctx);
	rsa_q = BN_CTX_get(ctx);
	rsa_dmp1 = BN_CTX_get(ctx);
	rsa_dmq1 = BN_CTX_get(ctx);
	rsa_iqmp = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!rsa_p || !rsa_q || !rsa_dmp1 || !rsa_dmq1 || !rsa_iqmp ||
			!argument || !result)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(rsa_p, p->top) || !bn_wexpand(rsa_q, q->top) ||
			!bn_wexpand(rsa_dmp1, dmp1->top) ||
			!bn_wexpand(rsa_dmq1, dmq1->top) ||
			!bn_wexpand(rsa_iqmp, iqmp->top) ||
			!bn_wexpand(argument, a->top) ||
			!bn_wexpand(result, p->top + q->top))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_CRT;
	sw_param.up.crt.p.nbytes = BN_bn2bin(p, (unsigned char *)rsa_p->d);
	sw_param.up.crt.p.value = (unsigned char *)rsa_p->d;
	sw_param.up.crt.q.nbytes = BN_bn2bin(q, (unsigned char *)rsa_q->d);
	sw_param.up.crt.q.value = (unsigned char *)rsa_q->d;
	sw_param.up.crt.dmp1.nbytes = BN_bn2bin(dmp1,
		(unsigned char *)rsa_dmp1->d);
	sw_param.up.crt.dmp1.value = (unsigned char *)rsa_dmp1->d;
	sw_param.up.crt.dmq1.nbytes = BN_bn2bin(dmq1,
		(unsigned char *)rsa_dmq1->d);
	sw_param.up.crt.dmq1.value = (unsigned char *)rsa_dmq1->d;
	sw_param.up.crt.iqmp.nbytes = BN_bn2bin(iqmp,
		(unsigned char *)rsa_iqmp->d);
	sw_param.up.crt.iqmp.value = (unsigned char *)rsa_iqmp->d;
	/* Attach the key params */
	sw_status = p_CSwift_AttachKeyParam(hac, &sw_param);
	switch(sw_status)
		{
	case SW_OK:
		break;
	case SW_ERR_INPUT_SIZE:
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,
			ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
		goto err;
	default:
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		}
		goto err;
		}
	/* Prepare the argument and response */
	arg.nbytes = BN_bn2bin(a, (unsigned char *)argument->d);
	arg.value = (unsigned char *)argument->d;
	res.nbytes = 2 * BN_num_bytes(p);
	memset(result->d, 0, res.nbytes);
	res.value = (unsigned char *)result->d;
	/* Perform the operation */
	if((sw_status = p_CSwift_SimpleRequest(hac, SW_CMD_MODEXP_CRT, &arg, 1,
		&res, 1)) != SW_OK)
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		goto err;
		}
	/* Convert the response */
	BN_bin2bn((unsigned char *)result->d, res.nbytes, r);
	to_return = 1;
err:
	if(acquired)
		release_context(hac);
	if(rsa_p) ctx->tos--;
	if(rsa_q) ctx->tos--;
	if(rsa_dmp1) ctx->tos--;
	if(rsa_dmq1) ctx->tos--;
	if(rsa_iqmp) ctx->tos--;
	if(argument) ctx->tos--;
	if(result) ctx->tos--;
	return to_return;
	}
 
static int cswift_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	BN_CTX *ctx;
	int to_return = 0;

	if((ctx = BN_CTX_new()) == NULL)
		goto err;
	if(!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp)
		{
		ENGINEerr(ENGINE_F_CSWIFT_RSA_MOD_EXP,ENGINE_R_MISSING_KEY_COMPONENTS);
		goto err;
		}
	to_return = cswift_mod_exp_crt(r0, I, rsa->p, rsa->q, rsa->dmp1,
		rsa->dmq1, rsa->iqmp, ctx);
err:
	if(ctx)
		BN_CTX_free(ctx);
	return to_return;
	}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int cswift_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return cswift_mod_exp(r, a, p, m, ctx);
	}

static DSA_SIG *cswift_dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa)
	{
	SW_CONTEXT_HANDLE hac;
	SW_PARAM sw_param;
	SW_STATUS sw_status;
	SW_LARGENUMBER arg, res;
	unsigned char *ptr;
	BN_CTX *ctx;
	BIGNUM *dsa_p = NULL;
	BIGNUM *dsa_q = NULL;
	BIGNUM *dsa_g = NULL;
	BIGNUM *dsa_key = NULL;
	BIGNUM *result = NULL;
	DSA_SIG *to_return = NULL;
	int acquired = 0;

	if((ctx = BN_CTX_new()) == NULL)
		goto err;
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	dsa_p = BN_CTX_get(ctx);
	dsa_q = BN_CTX_get(ctx);
	dsa_g = BN_CTX_get(ctx);
	dsa_key = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!dsa_p || !dsa_q || !dsa_g || !dsa_key || !result)
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(dsa_p, dsa->p->top) ||
			!bn_wexpand(dsa_q, dsa->q->top) ||
			!bn_wexpand(dsa_g, dsa->g->top) ||
			!bn_wexpand(dsa_key, dsa->priv_key->top) ||
			!bn_wexpand(result, dsa->p->top))
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_DSA;
	sw_param.up.dsa.p.nbytes = BN_bn2bin(dsa->p,
				(unsigned char *)dsa_p->d);
	sw_param.up.dsa.p.value = (unsigned char *)dsa_p->d;
	sw_param.up.dsa.q.nbytes = BN_bn2bin(dsa->q,
				(unsigned char *)dsa_q->d);
	sw_param.up.dsa.q.value = (unsigned char *)dsa_q->d;
	sw_param.up.dsa.g.nbytes = BN_bn2bin(dsa->g,
				(unsigned char *)dsa_g->d);
	sw_param.up.dsa.g.value = (unsigned char *)dsa_g->d;
	sw_param.up.dsa.key.nbytes = BN_bn2bin(dsa->priv_key,
				(unsigned char *)dsa_key->d);
	sw_param.up.dsa.key.value = (unsigned char *)dsa_key->d;
	/* Attach the key params */
	sw_status = p_CSwift_AttachKeyParam(hac, &sw_param);
	switch(sw_status)
		{
	case SW_OK:
		break;
	case SW_ERR_INPUT_SIZE:
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,
			ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
		goto err;
	default:
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		}
		goto err;
		}
	/* Prepare the argument and response */
	arg.nbytes = dlen;
	arg.value = (unsigned char *)dgst;
	res.nbytes = BN_num_bytes(dsa->p);
	memset(result->d, 0, res.nbytes);
	res.value = (unsigned char *)result->d;
	/* Perform the operation */
	sw_status = p_CSwift_SimpleRequest(hac, SW_CMD_DSS_SIGN, &arg, 1,
		&res, 1);
	if(sw_status != SW_OK)
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_DSA_SIGN,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		goto err;
		}
	/* Convert the response */
	ptr = (unsigned char *)result->d;
	if((to_return = DSA_SIG_new()) == NULL)
		goto err;
	to_return->r = BN_bin2bn((unsigned char *)result->d, 20, NULL);
	to_return->s = BN_bin2bn((unsigned char *)result->d + 20, 20, NULL);

err:
	if(acquired)
		release_context(hac);
	if(dsa_p) ctx->tos--;
	if(dsa_q) ctx->tos--;
	if(dsa_g) ctx->tos--;
	if(dsa_key) ctx->tos--;
	if(result) ctx->tos--;
	if(ctx)
		BN_CTX_free(ctx);
	return to_return;
	}

static int cswift_dsa_verify(const unsigned char *dgst, int dgst_len,
				DSA_SIG *sig, DSA *dsa)
	{
	SW_CONTEXT_HANDLE hac;
	SW_PARAM sw_param;
	SW_STATUS sw_status;
	SW_LARGENUMBER arg[2], res;
	unsigned long sig_result;
	BN_CTX *ctx;
	BIGNUM *dsa_p = NULL;
	BIGNUM *dsa_q = NULL;
	BIGNUM *dsa_g = NULL;
	BIGNUM *dsa_key = NULL;
	BIGNUM *argument = NULL;
	int to_return = -1;
	int acquired = 0;

	if((ctx = BN_CTX_new()) == NULL)
		goto err;
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	dsa_p = BN_CTX_get(ctx);
	dsa_q = BN_CTX_get(ctx);
	dsa_g = BN_CTX_get(ctx);
	dsa_key = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	if(!dsa_p || !dsa_q || !dsa_g || !dsa_key || !argument)
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(dsa_p, dsa->p->top) ||
			!bn_wexpand(dsa_q, dsa->q->top) ||
			!bn_wexpand(dsa_g, dsa->g->top) ||
			!bn_wexpand(dsa_key, dsa->pub_key->top) ||
			!bn_wexpand(argument, 40))
		{
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_DSA;
	sw_param.up.dsa.p.nbytes = BN_bn2bin(dsa->p,
				(unsigned char *)dsa_p->d);
	sw_param.up.dsa.p.value = (unsigned char *)dsa_p->d;
	sw_param.up.dsa.q.nbytes = BN_bn2bin(dsa->q,
				(unsigned char *)dsa_q->d);
	sw_param.up.dsa.q.value = (unsigned char *)dsa_q->d;
	sw_param.up.dsa.g.nbytes = BN_bn2bin(dsa->g,
				(unsigned char *)dsa_g->d);
	sw_param.up.dsa.g.value = (unsigned char *)dsa_g->d;
	sw_param.up.dsa.key.nbytes = BN_bn2bin(dsa->pub_key,
				(unsigned char *)dsa_key->d);
	sw_param.up.dsa.key.value = (unsigned char *)dsa_key->d;
	/* Attach the key params */
	sw_status = p_CSwift_AttachKeyParam(hac, &sw_param);
	switch(sw_status)
		{
	case SW_OK:
		break;
	case SW_ERR_INPUT_SIZE:
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,
			ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
		goto err;
	default:
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		}
		goto err;
		}
	/* Prepare the argument and response */
	arg[0].nbytes = dgst_len;
	arg[0].value = (unsigned char *)dgst;
	arg[1].nbytes = 40;
	arg[1].value = (unsigned char *)argument->d;
	memset(arg[1].value, 0, 40);
	BN_bn2bin(sig->r, arg[1].value + 20 - BN_num_bytes(sig->r));
	BN_bn2bin(sig->s, arg[1].value + 40 - BN_num_bytes(sig->s));
	res.nbytes = 4; /* unsigned long */
	res.value = (unsigned char *)(&sig_result);
	/* Perform the operation */
	sw_status = p_CSwift_SimpleRequest(hac, SW_CMD_DSS_VERIFY, arg, 2,
		&res, 1);
	if(sw_status != SW_OK)
		{
		char tmpbuf[20];
		ENGINEerr(ENGINE_F_CSWIFT_DSA_VERIFY,ENGINE_R_REQUEST_FAILED);
		sprintf(tmpbuf, "%ld", sw_status);
		ERR_add_error_data(2, "CryptoSwift error number is ",tmpbuf);
		goto err;
		}
	/* Convert the response */
	to_return = ((sig_result == 0) ? 0 : 1);

err:
	if(acquired)
		release_context(hac);
	if(dsa_p) ctx->tos--;
	if(dsa_q) ctx->tos--;
	if(dsa_g) ctx->tos--;
	if(dsa_key) ctx->tos--;
	if(argument) ctx->tos--;
	if(ctx)
		BN_CTX_free(ctx);
	return to_return;
	}

/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int cswift_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return cswift_mod_exp(r, a, p, m, ctx);
	}

#endif /* !NO_HW_CSWIFT */
#endif /* !NO_HW */
