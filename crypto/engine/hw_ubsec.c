/* crypto/engine/hw_ubsec.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 *
 * Cloned shamelessly by Joe Tardo. 
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
#include <string.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include <openssl/bn.h>
#include "engine_int.h"
#include <openssl/engine.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_UBSEC

#undef NOT_USED

#ifdef FLAT_INC
#include "hw_ubsec.h"
#else
#include "vendor_defns/hw_ubsec.h"
#endif

static int ubsec_init(void);
static int ubsec_finish(void);
static int ubsec_ctrl(int cmd, long i, void *p, void (*f)());
static int ubsec_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);
static int ubsec_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *q, const BIGNUM *dp,
			const BIGNUM *dq, const BIGNUM *qinv, BN_CTX *ctx);
#ifndef OPENSSL_NO_RSA
static int ubsec_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa);
#endif
static int ubsec_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
#ifndef OPENSSL_NO_DSA
#if NOT_USED
static int ubsec_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
		BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
		BN_CTX *ctx, BN_MONT_CTX *in_mont);
static int ubsec_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
		const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
		BN_MONT_CTX *m_ctx);
#endif
static DSA_SIG *ubsec_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int ubsec_dsa_verify(const unsigned char *dgst, int dgst_len,
                                DSA_SIG *sig, DSA *dsa);
#endif
#ifndef OPENSSL_NO_DH
static int ubsec_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a,
		const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
		BN_MONT_CTX *m_ctx);
static int ubsec_dh_compute_key(unsigned char *key,BIGNUM *pub_key,DH *dh);
static int ubsec_dh_generate_key(DH *dh);
#endif

#if NOT_USED
static int ubsec_rand_bytes(unsigned char *buf, int num);
static int ubsec_rand_status(void);
#endif
 
#ifndef OPENSSL_NO_RSA
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD ubsec_rsa =
	{
	"UBSEC RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	ubsec_rsa_mod_exp,
	ubsec_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};
#endif

#ifndef OPENSSL_NO_DSA
/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD ubsec_dsa =
	{
	"UBSEC DSA method",
	ubsec_dsa_do_sign,  /* dsa_do_sign */
	NULL,               /* dsa_sign_setup */
	ubsec_dsa_verify,   /* dsa_do_verify */
	NULL,               /* ubsec_dsa_mod_exp */ /* dsa_mod_exp */
	NULL,               /* ubsec_mod_exp_dsa */ /* bn_mod_exp */
	NULL,               /* init */
	NULL,               /* finish */
	0,                  /* flags */
	NULL                /* app_data */
	};
#endif

#ifndef OPENSSL_NO_DH
/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD ubsec_dh =
	{
	"UBSEC DH method",
	ubsec_dh_generate_key,
	ubsec_dh_compute_key,
	ubsec_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};
#endif

#ifdef NOT_USED
/* Our internal RAND_METHOD that we provide pointers to */
static RAND_METHOD ubsec_rand = {
  NULL,              /*void (*seed)(const void *buf, int num);*/
  ubsec_rand_bytes,  /*int (*bytes)(unsigned char *buf, int num);*/
  NULL,              /*void (*cleanup)(void);*/
  NULL,              /*void (*add)(const void *buf, int num, double entropy);*/
  ubsec_rand_bytes,  /*int (*pseudorand)(unsigned char *buf, int num);*/
  NULL,              /*int (*status)(void);*/
};
#endif

/* Constants used when creating the ENGINE */
static const char *engine_ubsec_id = "ubsec";
static const char *engine_ubsec_name = "UBSEC hardware engine support";

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_ubsec()
	{

#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *meth1;
#endif

#ifndef OPENSSL_NO_DH
#ifndef HAVE_UBSEC_DH
	const DH_METHOD *meth3;
#endif /* HAVE_UBSEC_DH */
#endif

	ENGINE *ret = ENGINE_new();

	if(!ret)
		return NULL;

	if(!ENGINE_set_id(ret, engine_ubsec_id) ||
			!ENGINE_set_name(ret, engine_ubsec_name) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(ret, &ubsec_rsa) ||
#endif
#ifndef OPENSSL_NO_DSA
			!ENGINE_set_DSA(ret, &ubsec_dsa) ||
#endif
#ifndef OPENSSL_NO_DH
			!ENGINE_set_DH(ret, &ubsec_dh) ||
#endif
			!ENGINE_set_BN_mod_exp(ret, ubsec_mod_exp) ||
			!ENGINE_set_BN_mod_exp_crt(ret, ubsec_mod_exp_crt) ||
			!ENGINE_set_init_function(ret, ubsec_init) ||
			!ENGINE_set_finish_function(ret, ubsec_finish) ||
			!ENGINE_set_ctrl_function(ret, ubsec_ctrl))
		{
		ENGINE_free(ret);
		return NULL;
		}

#ifndef OPENSSL_NO_RSA
	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the Broadcom-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1 = RSA_PKCS1_SSLeay();
	ubsec_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
	ubsec_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
	ubsec_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
	ubsec_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
#endif

#ifndef OPENSSL_NO_DH
#ifndef HAVE_UBSEC_DH
	/* Much the same for Diffie-Hellman */
	meth3 = DH_OpenSSL();
	ubsec_dh.generate_key = meth3->generate_key;
	ubsec_dh.compute_key = meth3->compute_key;
#endif /* HAVE_UBSEC_DH */
#endif
	
	return ret;
	}

/* This is a process-global DSO handle used for loading and unloading
 * the UBSEC library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */

static DSO *ubsec_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */

static t_UBSEC_ubsec_bytes_to_bits *p_UBSEC_ubsec_bytes_to_bits = NULL;
static t_UBSEC_ubsec_bits_to_bytes *p_UBSEC_ubsec_bits_to_bytes = NULL;
static t_UBSEC_ubsec_open *p_UBSEC_ubsec_open = NULL;
static t_UBSEC_ubsec_close *p_UBSEC_ubsec_close = NULL;
#ifndef OPENSSL_NO_DH
static t_UBSEC_diffie_hellman_generate_ioctl 
	*p_UBSEC_diffie_hellman_generate_ioctl = NULL;
static t_UBSEC_diffie_hellman_agree_ioctl *p_UBSEC_diffie_hellman_agree_ioctl = NULL;
#endif
static t_UBSEC_rsa_mod_exp_ioctl *p_UBSEC_rsa_mod_exp_ioctl = NULL;
static t_UBSEC_rsa_mod_exp_crt_ioctl *p_UBSEC_rsa_mod_exp_crt_ioctl = NULL;
#ifndef OPENSSL_NO_DSA
static t_UBSEC_dsa_sign_ioctl *p_UBSEC_dsa_sign_ioctl = NULL;
static t_UBSEC_dsa_verify_ioctl *p_UBSEC_dsa_verify_ioctl = NULL;
#endif
static t_UBSEC_math_accelerate_ioctl *p_UBSEC_math_accelerate_ioctl = NULL;
static t_UBSEC_rng_ioctl *p_UBSEC_rng_ioctl = NULL;
static t_UBSEC_max_key_len_ioctl *p_UBSEC_max_key_len_ioctl = NULL;

static int max_key_len = 1024; /* ??? */

/* 
 * These are the static string constants for the DSO file name and the function
 * symbol names to bind to. 
 */

static const char *UBSEC_LIBNAME = "libubsec.so";
static const char *UBSEC_F1 = "ubsec_bytes_to_bits";
static const char *UBSEC_F2 = "ubsec_bits_to_bytes";
static const char *UBSEC_F3 = "ubsec_open";
static const char *UBSEC_F4 = "ubsec_close";
#ifndef OPENSSL_NO_DH
static const char *UBSEC_F5 = "diffie_hellman_generate_ioctl";
static const char *UBSEC_F6 = "diffie_hellman_agree_ioctl";
#endif
/* #ifndef OPENSSL_NO_RSA */
static const char *UBSEC_F7 = "rsa_mod_exp_ioctl";
static const char *UBSEC_F8 = "rsa_mod_exp_crt_ioctl";
/* #endif */
#ifndef OPENSSL_NO_DSA
static const char *UBSEC_F9 = "dsa_sign_ioctl";
static const char *UBSEC_F10 = "dsa_verify_ioctl";
#endif
static const char *UBSEC_F11 = "math_accelerate_ioctl";
static const char *UBSEC_F12 = "rng_ioctl";
static const char *UBSEC_F13 = "ubsec_max_key_len_ioctl";

/* (de)initialisation functions. */
static int ubsec_init(void)
	{
	t_UBSEC_ubsec_bytes_to_bits *p1;
	t_UBSEC_ubsec_bits_to_bytes *p2;
	t_UBSEC_ubsec_open *p3;
	t_UBSEC_ubsec_close *p4;
#ifndef OPENSSL_NO_DH
	t_UBSEC_diffie_hellman_generate_ioctl *p5;
	t_UBSEC_diffie_hellman_agree_ioctl *p6;
#endif
	t_UBSEC_rsa_mod_exp_ioctl *p7;
	t_UBSEC_rsa_mod_exp_crt_ioctl *p8;
#ifndef OPENSSL_NO_DSA
	t_UBSEC_dsa_sign_ioctl *p9;
	t_UBSEC_dsa_verify_ioctl *p10;
#endif
	t_UBSEC_math_accelerate_ioctl *p11;
	t_UBSEC_rng_ioctl *p12;
	t_UBSEC_max_key_len_ioctl *p13;
	int fd;

	if(ubsec_dso != NULL)
		{
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* 
	 * Attempt to load libubsec.so/ubsec.dll/whatever. 
	 */
	ubsec_dso = DSO_load(NULL, UBSEC_LIBNAME, NULL, 0);
	if(ubsec_dso == NULL)
		{
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_DSO_FAILURE);
		goto err;
		}

	if (
	!(p1 = (t_UBSEC_ubsec_bytes_to_bits *) DSO_bind_func(ubsec_dso, UBSEC_F1)) ||
	!(p2 = (t_UBSEC_ubsec_bits_to_bytes *) DSO_bind_func(ubsec_dso, UBSEC_F2)) ||
	!(p3 = (t_UBSEC_ubsec_open *) DSO_bind_func(ubsec_dso, UBSEC_F3)) ||
	!(p4 = (t_UBSEC_ubsec_close *) DSO_bind_func(ubsec_dso, UBSEC_F4)) ||
	!(p5 = (t_UBSEC_diffie_hellman_generate_ioctl *) 
				DSO_bind_func(ubsec_dso, UBSEC_F5)) ||
	!(p6 = (t_UBSEC_diffie_hellman_agree_ioctl *) 
				DSO_bind_func(ubsec_dso, UBSEC_F6)) ||
	!(p7 = (t_UBSEC_rsa_mod_exp_ioctl *) DSO_bind_func(ubsec_dso, UBSEC_F7)) ||
	!(p8 = (t_UBSEC_rsa_mod_exp_crt_ioctl *) DSO_bind_func(ubsec_dso, UBSEC_F8)) ||
	!(p9 = (t_UBSEC_dsa_sign_ioctl *) DSO_bind_func(ubsec_dso, UBSEC_F9)) ||
	!(p10 = (t_UBSEC_dsa_verify_ioctl *) DSO_bind_func(ubsec_dso, UBSEC_F10)) ||
	!(p11 = (t_UBSEC_math_accelerate_ioctl *) 
				DSO_bind_func(ubsec_dso, UBSEC_F11)) ||
	!(p12 = (t_UBSEC_rng_ioctl *) DSO_bind_func(ubsec_dso, UBSEC_F12)) ||
	!(p13 = (t_UBSEC_max_key_len_ioctl*) DSO_bind_func(ubsec_dso, UBSEC_F13)))
		{
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_DSO_FAILURE);
		goto err;
		}

	/* Copy the pointers */
	p_UBSEC_ubsec_bytes_to_bits = p1;
	p_UBSEC_ubsec_bits_to_bytes = p2;
	p_UBSEC_ubsec_open = p3;
	p_UBSEC_ubsec_close = p4;
#ifndef OPENSSL_NO_DH
	p_UBSEC_diffie_hellman_generate_ioctl = p5;
	p_UBSEC_diffie_hellman_agree_ioctl = p6;
#endif
#ifndef OPENSSL_NO_RSA
	p_UBSEC_rsa_mod_exp_ioctl = p7;
	p_UBSEC_rsa_mod_exp_crt_ioctl = p8;
#endif
#ifndef OPENSSL_NO_DSA
	p_UBSEC_dsa_sign_ioctl = p9;
	p_UBSEC_dsa_verify_ioctl = p10;
#endif
	p_UBSEC_math_accelerate_ioctl = p11;
	p_UBSEC_rng_ioctl = p12;
	p_UBSEC_max_key_len_ioctl = p13;

	/* Perform an open to see if there's actually any unit running. */
	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0)
	        {
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	if (p_UBSEC_max_key_len_ioctl(fd, &max_key_len) != 0)
	        {
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		p_UBSEC_ubsec_close(fd);
		goto err;
		}
	
	p_UBSEC_ubsec_close(fd);
	return 1;

err:
	if(ubsec_dso)
		DSO_free(ubsec_dso);
	p_UBSEC_ubsec_bytes_to_bits = NULL;
	p_UBSEC_ubsec_bits_to_bytes = NULL;
	p_UBSEC_ubsec_open = NULL;
	p_UBSEC_ubsec_close = NULL;
#ifndef OPENSSL_NO_DH
	p_UBSEC_diffie_hellman_generate_ioctl = NULL;
	p_UBSEC_diffie_hellman_agree_ioctl = NULL;
#endif
#ifndef OPENSSL_NO_RSA
	p_UBSEC_rsa_mod_exp_ioctl = NULL;
	p_UBSEC_rsa_mod_exp_crt_ioctl = NULL;
#endif
#ifndef OPENSSL_NO_DSA
	p_UBSEC_dsa_sign_ioctl = NULL;
	p_UBSEC_dsa_verify_ioctl = NULL;
#endif
	p_UBSEC_math_accelerate_ioctl = NULL;
	p_UBSEC_rng_ioctl = NULL;
	p_UBSEC_max_key_len_ioctl = NULL;

	return 0;
	}

static int ubsec_finish(void )
	{
	if(ubsec_dso == NULL)
		{
		ENGINEerr(ENGINE_F_UBSEC_FINISH, ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(ubsec_dso))
		{
		ENGINEerr(ENGINE_F_UBSEC_FINISH, ENGINE_R_DSO_FAILURE);
		return 0;
		}
	ubsec_dso = NULL;
	p_UBSEC_ubsec_bytes_to_bits = NULL;
	p_UBSEC_ubsec_bits_to_bytes = NULL;
	p_UBSEC_ubsec_open = NULL;
	p_UBSEC_ubsec_close = NULL;
#ifndef OPENSSL_NO_DH
	p_UBSEC_diffie_hellman_generate_ioctl = NULL;
	p_UBSEC_diffie_hellman_agree_ioctl = NULL;
#endif
#ifndef OPENSSL_NO_RSA
	p_UBSEC_rsa_mod_exp_ioctl = NULL;
	p_UBSEC_rsa_mod_exp_crt_ioctl = NULL;
#endif
#ifndef OPENSSL_NO_DSA
	p_UBSEC_dsa_sign_ioctl = NULL;
	p_UBSEC_dsa_verify_ioctl = NULL;
#endif
	p_UBSEC_math_accelerate_ioctl = NULL;
	p_UBSEC_rng_ioctl = NULL;
	p_UBSEC_max_key_len_ioctl = NULL;
	return 1;
	}

static int ubsec_ctrl(int cmd, long i, void *p, void (*f)())
	{
	switch(cmd)
		{
	default:
		break;
		}
	ENGINEerr(ENGINE_F_UBSEC_CTRL,ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
	return 0;
	}

static int ubsec_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx)
	{
	int     ret = 0;
	int 	r_len = 0;
	int 	fd;

	if(ubsec_dso == NULL)
	        {
		ENGINEerr(ENGINE_F_UBSEC_MOD_EXP, ENGINE_R_NOT_LOADED);
		goto err;
		}

	r_len = BN_num_bits(m);

 	/* Perform in software if modulus is too large for hardware. */

	if (r_len > max_key_len) 
	        {
		ENGINE *e;
		ENGINEerr(ENGINE_F_UBSEC_MOD_EXP, ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp(r, a, p, m, ctx);
		goto err;
		} 

	if (!bn_wexpand(r, m->top))
	        {
		ENGINEerr(ENGINE_F_UBSEC_MOD_EXP, ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	memset(r->d, 0, BN_num_bytes(m));

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
	        {
		ENGINE *e;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp(r, a, p, m, ctx);
		goto err;
		}

	if (p_UBSEC_rsa_mod_exp_ioctl(fd, 
				      (unsigned char *)a->d, BN_num_bits(a),
				      (unsigned char *)m->d, BN_num_bits(m), 
				      (unsigned char *)p->d, BN_num_bits(p), 
				      (unsigned char *)r->d, &r_len) != 0)
	        {
		/* Hardware's a no go, failover to software */
		ENGINE *e;

		ENGINEerr(ENGINE_F_UBSEC_MOD_EXP, ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);

	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp(r, a, p, m, ctx);
		goto err;
		}
	
	p_UBSEC_ubsec_close(fd);

	r->top = (BN_num_bits(m)+BN_BITS2-1)/BN_BITS2;

	ret = 1;
err:
	return ret;
	}

static int ubsec_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *q, const BIGNUM *dp,
			const BIGNUM *dq, const BIGNUM *qinv, BN_CTX *ctx)
        {

	int	y_len,
		m_len,
		fd,
                ret = 0;

	m_len = BN_num_bytes(p) + BN_num_bytes(q) + 1;
	y_len = BN_num_bits(p) + BN_num_bits(q);

 	/* Perform in software if modulus is too large for hardware. */

	if (y_len > max_key_len) 
	        {
	        ENGINE *e;

		ENGINEerr(ENGINE_F_UBSEC_RSA_MOD_EXP_CRT, ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL);
	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp_crt(r, a, p, q, dp, dq, qinv, ctx);

		goto err;
	        }

	if (!bn_wexpand(r, p->top + q->top + 1)) 
	        {
		ENGINEerr(ENGINE_F_UBSEC_RSA_MOD_EXP_CRT, ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	        }

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
	        {
	        ENGINE *e;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp_crt(r, a, p, q, dp, dq, qinv, ctx);
		goto err;
		}

	if (p_UBSEC_rsa_mod_exp_crt_ioctl(fd,
		(unsigned char *)a->d, BN_num_bits(a), 
		(unsigned char *)qinv->d, BN_num_bits(qinv),
		(unsigned char *)dp->d, BN_num_bits(dp),
		(unsigned char *)p->d, BN_num_bits(p),
		(unsigned char *)dq->d, BN_num_bits(dq),
		(unsigned char *)q->d, BN_num_bits(q),
		(unsigned char *)r->d,  &y_len) != 0) 
	        {
	        ENGINE *e;
		p_UBSEC_ubsec_close(fd);
		ENGINEerr(ENGINE_F_UBSEC_RSA_MOD_EXP_CRT, ENGINE_R_UNIT_FAILURE);
	        e = ENGINE_openssl();
	        ret = e->bn_mod_exp_crt(r, a, p, q, dp, dq, qinv, ctx);

	        goto err;
	        }

	p_UBSEC_ubsec_close(fd);
	
	r->top = (BN_num_bits(p) + BN_num_bits(q) + BN_BITS2 - 1)/BN_BITS2;
	
	ret = 1;
 err:
	return(ret);
	}

#ifndef OPENSSL_NO_RSA
static int ubsec_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	BN_CTX *ctx;
	int ret = 0;

	if ((ctx = BN_CTX_new()) == NULL) goto err;

	if (!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp)
		{
		ENGINEerr(ENGINE_F_UBSEC_RSA_MOD_EXP, ENGINE_R_MISSING_KEY_COMPONENTS);
		goto err;
		}

 	/* Perform in software if the key is too large for hardware. */

	if ((BN_num_bits(rsa->p) > (max_key_len / 2)) && 
	    (BN_num_bits(rsa->q) > (max_key_len / 2 )))
	        {
		const RSA_METHOD *meth;
		meth = RSA_PKCS1_SSLeay();
		ret = meth->rsa_mod_exp(r0, I, rsa);
	        } 
	else 
	        {
		ret = ubsec_mod_exp_crt(r0, 
					I, 
					rsa->p, 
					rsa->q, 
					rsa->dmp1,
					rsa->dmq1, 
					rsa->iqmp, 
					ctx);
		}

err:
	if (ctx) BN_CTX_free(ctx);
	return ret;
	}
#endif

#ifndef OPENSSL_NO_DSA
#if NOT_USED
static int ubsec_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
		BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
		BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	BIGNUM t;
	int ret = 0;
 
	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!ubsec_mod_exp(rr,a1,p1,m,ctx)) goto err;
	/* let t = a2 ^ p2 mod m */
	if (!ubsec_mod_exp(&t,a2,p2,m,ctx)) goto err;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr,rr,&t,m,ctx)) goto err;
	ret = 1;
err:
	BN_free(&t);
	return ret;
	}

static int ubsec_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
		const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
		BN_MONT_CTX *m_ctx)
	{
	return ubsec_mod_exp(r, a, p, m, ctx);
	}
#endif
#endif

/*
 * This function is aliased to mod_exp (with the mont stuff dropped).
 */
static int ubsec_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	int ret = 0;


#ifndef OPENSSL_NO_RSA
 	/* Perform in software if the modulus is too large for hardware. */

	if (BN_num_bits(m) > max_key_len) 
	        {
		const RSA_METHOD *meth;
		meth = RSA_PKCS1_SSLeay();
		ret = meth->bn_mod_exp(r, a, p, m, ctx, m_ctx);
		} 
	else 
#endif
	        {
		ret = ubsec_mod_exp(r, a, p, m, ctx);
		}
	
	return ret;
}

#ifndef OPENSSL_NO_DSA
static DSA_SIG *ubsec_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
	{
	DSA_SIG  *ret  = NULL;
	int      s_len = 160, 
	         r_len = 160, 
                 d_len, 
	         fd;
	BIGNUM   m, 
	         *r    = NULL, 
                 *s    = NULL;

	BN_init(&m);
	s = BN_new();
	r = BN_new();
	if ((s == NULL) || (r==NULL)) goto err;

	d_len = p_UBSEC_ubsec_bytes_to_bits((unsigned char *)dgst, dlen);

        if(!bn_wexpand(r, (160+BN_BITS2-1)/BN_BITS2) ||
       	   (!bn_wexpand(s, (160+BN_BITS2-1)/BN_BITS2))) {
		ENGINEerr(ENGINE_F_UBSEC_DSA_SIGN, ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	}

	if (BN_bin2bn(dgst,dlen,&m) == NULL) {
		ENGINEerr(ENGINE_F_UBSEC_DSA_SIGN, ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	} 

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0)
		{
		const DSA_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		meth = DSA_OpenSSL();
		ret = meth->dsa_do_sign(dgst, dlen, dsa);
		goto err;
		}

	if (p_UBSEC_dsa_sign_ioctl(fd, 
				   0, /* compute hash before signing */
				   (unsigned char *)dgst, d_len,
				   NULL, 0, /* compute random value */
				   (unsigned char *)dsa->p->d, BN_num_bits(dsa->p), 
				   (unsigned char *)dsa->q->d, BN_num_bits(dsa->q),
				   (unsigned char *)dsa->g->d, BN_num_bits(dsa->g),
				   (unsigned char *)dsa->priv_key->d, BN_num_bits(dsa->priv_key),
				   (unsigned char *)r->d, &r_len,
				   (unsigned char *)s->d, &s_len ) != 0) 
	        {
		/* Hardware's a no go, failover to software */
		const DSA_METHOD *meth;

		ENGINEerr(ENGINE_F_UBSEC_DSA_SIGN, ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);

		meth = DSA_OpenSSL();
		ret = meth->dsa_do_sign(dgst, dlen, dsa);

		goto err;
	}

	p_UBSEC_ubsec_close(fd);

	r->top = (160+BN_BITS2-1)/BN_BITS2;
	s->top = (160+BN_BITS2-1)/BN_BITS2;

	ret = DSA_SIG_new();
	if(ret == NULL) {
		ENGINEerr(ENGINE_F_UBSEC_DSA_SIGN, ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	}

	ret->r = r;
	ret->s = s;
err:
	if (!ret)
	        {
		if (r) BN_free(r);
		if (s) BN_free(s);
		}                          
	BN_clear_free(&m);
	return ret;
}

static int ubsec_dsa_verify(const unsigned char *dgst, int dgst_len,
                                DSA_SIG *sig, DSA *dsa)
	{
	int      v_len, 
	         d_len,
	         ret      = 0,
	         fd;
	BIGNUM   v;

	BN_init(&v);

	if (!bn_wexpand(&v, dsa->p->top)) 
        {
		ENGINEerr(ENGINE_F_UBSEC_DSA_VERIFY ,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
	}

	v_len = BN_num_bits(dsa->p);

	d_len = p_UBSEC_ubsec_bytes_to_bits((unsigned char *)dgst, dgst_len);

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
        	{
		const DSA_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		meth = DSA_OpenSSL();
		ret = meth->dsa_do_verify(dgst, dgst_len, sig, dsa);
		goto err;
		}

	if (p_UBSEC_dsa_verify_ioctl(fd, 
				     0, /* compute hash before signing */
				     (unsigned char *)dgst, d_len,
				     (unsigned char *)dsa->p->d, BN_num_bits(dsa->p), 
				     (unsigned char *)dsa->q->d, BN_num_bits(dsa->q),
				     (unsigned char *)dsa->g->d, BN_num_bits(dsa->g),
				     (unsigned char *)dsa->pub_key->d, BN_num_bits(dsa->pub_key),
				     (unsigned char *)sig->r->d, BN_num_bits(sig->r),
				     (unsigned char *)sig->s->d, BN_num_bits(sig->s),
				     (unsigned char *)v.d, &v_len) != 0) 
	        {
		/* Hardware's a no go, failover to software */
		const DSA_METHOD *meth;
		
		ENGINEerr(ENGINE_F_UBSEC_DSA_VERIFY , ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);

		meth = DSA_OpenSSL();
		ret = meth->dsa_do_verify(dgst, dgst_len, sig, dsa);

		goto err;
		}

	p_UBSEC_ubsec_close(fd);

	ret = 1;
err:
	BN_clear_free(&v);
	return ret;
	}
#endif

#ifndef OPENSSL_NO_DH
/*
 * This function is aliased to mod_exp.
 */
static int ubsec_mod_exp_dh(DH *dh,
			    BIGNUM *r,
			    BIGNUM *a,
			    const BIGNUM *p,
			    const BIGNUM *m,
			    BN_CTX *ctx,
			    BN_MONT_CTX *m_ctx)
	{
	return ubsec_mod_exp(r, a, p, m, ctx);
	}
#endif

static int ubsec_dh_compute_key (unsigned char *key,BIGNUM *pub_key,DH *dh)
        {
	int      ret      = -1,
	         k_len,
	         fd;
	  
	k_len = BN_num_bits(dh->p);
	  
	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
	        {
		const DH_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		meth = DH_OpenSSL();
		ret = meth->compute_key(key, pub_key, dh);
		goto err;
		}
	  
	if (p_UBSEC_diffie_hellman_agree_ioctl(fd,
					       (unsigned char *)dh->priv_key->d, BN_num_bits(dh->priv_key),
					       (unsigned char *)pub_key->d, BN_num_bits(pub_key),
					       (unsigned char *)dh->p->d, BN_num_bits(dh->p),
					       key, &k_len) != 0)
	        {
	        /* Hardware's a no go, failover to software */
		const DH_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_DH_COMPUTE_KEY, ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);
		
		meth = DH_OpenSSL();
		ret = meth->compute_key(key, pub_key, dh);
		
		goto err;
		}

	p_UBSEC_ubsec_close(fd);
	  
	ret = p_UBSEC_ubsec_bits_to_bytes(k_len); 
err:
	return ret;
	}

static int ubsec_dh_generate_key (DH *dh) 
        {
	int      ret               = 0,
	         random_bits       = 0,
                 pub_key_len       = 0,
	         priv_key_len      = 0,
	         fd;
	BIGNUM   *pub_key          = NULL;
	BIGNUM   *priv_key         = NULL;

	/*  
	 *  How many bits should Random x be? dh_key.c 
	 *  sets the range from 0 to num_bits(modulus) ??? 
	 */
  
	if (dh->priv_key == NULL) 
	        {
		priv_key = BN_new();
		if (priv_key == NULL) goto err;
		priv_key_len = BN_num_bits(dh->p);
		bn_wexpand(priv_key, dh->p->top);
		do
			if (!BN_rand_range(priv_key, dh->p)) goto err;
		while (BN_is_zero(priv_key));
		random_bits = BN_num_bits(priv_key);
		} 
	else 
	        {
		priv_key = dh->priv_key;
		}

	if (dh->pub_key == NULL)
	        {
		pub_key = BN_new();
		pub_key_len = BN_num_bits(dh->p);
		bn_wexpand(pub_key, dh->p->top);
		if(pub_key == NULL) goto err;
		}
	else 
	        {
		pub_key = dh->pub_key;
		}

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
	        {
		const DH_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
      		meth = DH_OpenSSL();
		ret = meth->generate_key(dh);
		goto err;
		}
  
	if (p_UBSEC_diffie_hellman_generate_ioctl(fd,
						  (unsigned char *)priv_key->d, &priv_key_len,
						  (unsigned char *)pub_key->d,  &pub_key_len,
						  (unsigned char *)dh->g->d, BN_num_bits(dh->g),
						  (unsigned char *)dh->p->d, BN_num_bits(dh->p),
						  0, 0, random_bits) != 0) 
	        {
		/* Hardware's a no go, failover to software */
		const DH_METHOD *meth;

		ENGINEerr(ENGINE_F_UBSEC_DH_COMPUTE_KEY, ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);

      		meth = DH_OpenSSL();
		ret = meth->generate_key(dh);

		goto err;
		}
  
	p_UBSEC_ubsec_close(fd);

	dh->pub_key = pub_key;
	dh->pub_key->top = (pub_key_len + BN_BITS2-1) / BN_BITS2;
	dh->priv_key = priv_key;
	dh->priv_key->top = (priv_key_len + BN_BITS2-1) / BN_BITS2;

	ret = 1;
err:
	return ret;
	}

#if NOT_USED
static int ubsec_rand_bytes(unsigned char * buf, 
			    int num)
        {
	int      ret      = 0,
	         fd;

	if ((fd = p_UBSEC_ubsec_open(UBSEC_KEY_DEVICE_NAME)) <= 0) 
	        {
		const RAND_METHOD *meth;
		ENGINEerr(ENGINE_F_UBSEC_INIT, ENGINE_R_UNIT_FAILURE);
		num = p_UBSEC_ubsec_bits_to_bytes(num);
		meth = RAND_SSLeay();
		meth->seed(buf, num);
		ret = meth->bytes(buf, num);
	        goto err;
		}

	num *= 8; /* bytes to bits */

	if (p_UBSEC_rng_ioctl(fd,
			      UBSEC_RNG_DIRECT,
			      buf,
			      &num) != 0)
	        {
		/* Hardware's a no go, failover to software */
		const RAND_METHOD *meth;

		ENGINEerr(ENGINE_F_UBSEC_RNG_BYTES, ENGINE_R_REQUEST_FAILED);
		p_UBSEC_ubsec_close(fd);

		num = p_UBSEC_ubsec_bits_to_bytes(num);
		meth = RAND_SSLeay();
		meth->seed(buf, num);
		ret = meth->bytes(buf, num);

	        goto err;
		}
  
	p_UBSEC_ubsec_close(fd);
  
	ret = 1;
err:
	return(ret);
	}

static int ubsec_rand_status(void)
	{
	return 0;
	}
#endif

#endif /* !OPENSSL_NO_HW_UBSEC */
#endif /* !OPENSSL_NO_HW */
