/* crypto/engine/engine_lib.c */
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

#include <openssl/crypto.h>
#include "cryptlib.h"
#include "engine_int.h"
#include <openssl/engine.h>

/* These pointers each have their own "functional reference" when they
 * are non-NULL. Similarly, when they are retrieved by a call to
 * ENGINE_get_default_[RSA|DSA|...] the returned pointer is also a
 * reference and the caller is responsible for freeing that when they
 * are finished with it (with a call to ENGINE_finish() *NOT* just
 * ENGINE_free()!!!!!!). */
static ENGINE *engine_def_rsa = NULL;
static ENGINE *engine_def_dsa = NULL;
static ENGINE *engine_def_dh = NULL;
static ENGINE *engine_def_rand = NULL;
static ENGINE *engine_def_bn_mod_exp = NULL;
static ENGINE *engine_def_bn_mod_exp_crt = NULL;
/* A static "once-only" flag used to control if/when the above were
 * initialised to suitable start-up defaults. */
static int engine_def_flag = 0;

/* This is used in certain static utility functions to save code
 * repetition for per-algorithm functions. */
typedef enum {
	ENGINE_TYPE_RSA,
	ENGINE_TYPE_DSA,
	ENGINE_TYPE_DH,
	ENGINE_TYPE_RAND,
	ENGINE_TYPE_BN_MOD_EXP,
	ENGINE_TYPE_BN_MOD_EXP_CRT
	} ENGINE_TYPE;

static void engine_def_check_util(ENGINE **def, ENGINE *val)
	{
	*def = val;
	val->struct_ref++;
	val->funct_ref++;
	}

/* In a slight break with convention - this static function must be
 * called *outside* any locking of CRYPTO_LOCK_ENGINE. */
static void engine_def_check(void)
	{
	ENGINE *e;
	if(engine_def_flag)
		return;
	e = ENGINE_get_first();
	if(e == NULL)
		/* The list is empty ... not much we can do! */
		return;
	/* We have a structural reference, see if getting a functional
	 * reference is possible. This is done to cope with init errors
	 * in the engine - the following locked code does a bunch of
	 * manual "ENGINE_init"s which do *not* allow such an init
	 * error so this is worth doing. */
	if(ENGINE_init(e))
		{
		CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
		/* Doing another check here prevents an obvious race
		 * condition because the whole function itself cannot
		 * be locked. */
		if(engine_def_flag)
			goto skip_set_defaults;
		/* OK, we got a functional reference, so we get one each
		 * for the defaults too. */
		engine_def_check_util(&engine_def_rsa, e);
		engine_def_check_util(&engine_def_dsa, e);
		engine_def_check_util(&engine_def_dh, e);
		engine_def_check_util(&engine_def_rand, e);
		engine_def_check_util(&engine_def_bn_mod_exp, e);
		engine_def_check_util(&engine_def_bn_mod_exp_crt, e);
		engine_def_flag = 1;
skip_set_defaults:
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		/* The "if" needs to be balanced out. */
		ENGINE_finish(e);
		}
	/* We need to balance out the fact we obtained a structural
	 * reference to begin with from ENGINE_get_first(). */
	ENGINE_free(e);
	}

/* Initialise a engine type for use (or up its functional reference count
 * if it's already in use). */
int ENGINE_init(ENGINE *e)
	{
	int to_return = 1;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_INIT,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if((e->funct_ref == 0) && e->init)
		/* This is the first functional reference and the engine
		 * requires initialisation so we do it now. */
		to_return = e->init();
	if(to_return)
		{
		/* OK, we return a functional reference which is also a
		 * structural reference. */
		e->struct_ref++;
		e->funct_ref++;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return to_return;
	}

/* Free a functional reference to a engine type */
int ENGINE_finish(ENGINE *e)
	{
	int to_return = 1;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_FINISH,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if((e->funct_ref == 1) && e->finish)
#if 0
		/* This is the last functional reference and the engine
		 * requires cleanup so we do it now. */
		to_return = e->finish();
	if(to_return)
		{
		/* Cleanup the functional reference which is also a
		 * structural reference. */
		e->struct_ref--;
		e->funct_ref--;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
#else
		/* I'm going to deliberately do a convoluted version of this
		 * piece of code because we don't want "finish" functions
		 * being called inside a locked block of code, if at all
		 * possible. I'd rather have this call take an extra couple
		 * of ticks than have throughput serialised on a externally-
		 * provided callback function that may conceivably never come
		 * back. :-( */
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		/* CODE ALERT: This *IS* supposed to be "=" and NOT "==" :-) */
		if((to_return = e->finish()))
			{
			CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
			/* Cleanup the functional reference which is also a
			 * structural reference. */
			e->struct_ref--;
			e->funct_ref--;
			CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
			}
		}
	else
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
#endif
	return to_return;
	}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
	const char *passphrase)
	{
	EVP_PKEY *pkey;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(e->funct_ref == 0)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	if (!e->load_privkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_NO_LOAD_FUNCTION);
		return 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	pkey = e->load_privkey(key_id, passphrase);
	if (!pkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_FAILED_LOADING_PRIVATE_KEY);
		return 0;
		}
	return pkey;
	}

EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
	const char *passphrase)
	{
	EVP_PKEY *pkey;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(e->funct_ref == 0)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	if (!e->load_pubkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_NO_LOAD_FUNCTION);
		return 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	pkey = e->load_pubkey(key_id, passphrase);
	if (!pkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_FAILED_LOADING_PUBLIC_KEY);
		return 0;
		}
	return pkey;
	}

/* Initialise a engine type for use (or up its functional reference count
 * if it's already in use). */
int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(e->struct_ref == 0)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ENGINE_R_NO_REFERENCE);
		return 0;
		}
	if (!e->ctrl)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ENGINE_R_NO_CONTROL_FUNCTION);
		return 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return e->ctrl(cmd, i, p, f);
	}

static ENGINE *engine_get_default_type(ENGINE_TYPE t)
	{
	ENGINE *ret = NULL;

	/* engine_def_check is lean and mean and won't replace any
	 * prior default engines ... so we must ensure that it is always
	 * the first function to get to touch the default values. */
	engine_def_check();
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	switch(t)
		{
	case ENGINE_TYPE_RSA:
		ret = engine_def_rsa; break;
	case ENGINE_TYPE_DSA:
		ret = engine_def_dsa; break;
	case ENGINE_TYPE_DH:
		ret = engine_def_dh; break;
	case ENGINE_TYPE_RAND:
		ret = engine_def_rand; break;
	case ENGINE_TYPE_BN_MOD_EXP:
		ret = engine_def_bn_mod_exp; break;
	case ENGINE_TYPE_BN_MOD_EXP_CRT:
		ret = engine_def_bn_mod_exp_crt; break;
		}
	/* Unforunately we can't do this work outside the lock with a
	 * call to ENGINE_init() because that would leave a race
	 * condition open. */
	if(ret)
		{
		ret->struct_ref++;
		ret->funct_ref++;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return ret;
	}

ENGINE *ENGINE_get_default_RSA(void)
	{
	return engine_get_default_type(ENGINE_TYPE_RSA);
	}

ENGINE *ENGINE_get_default_DSA(void)
	{
	return engine_get_default_type(ENGINE_TYPE_DSA);
	}

ENGINE *ENGINE_get_default_DH(void)
	{
	return engine_get_default_type(ENGINE_TYPE_DH);
	}

ENGINE *ENGINE_get_default_RAND(void)
	{
	return engine_get_default_type(ENGINE_TYPE_RAND);
	}

ENGINE *ENGINE_get_default_BN_mod_exp(void)
	{
	return engine_get_default_type(ENGINE_TYPE_BN_MOD_EXP);
	}

ENGINE *ENGINE_get_default_BN_mod_exp_crt(void)
	{
	return engine_get_default_type(ENGINE_TYPE_BN_MOD_EXP_CRT);
	}

static int engine_set_default_type(ENGINE_TYPE t, ENGINE *e)
	{
	ENGINE *old = NULL;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DEFAULT_TYPE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	/* engine_def_check is lean and mean and won't replace any
	 * prior default engines ... so we must ensure that it is always
	 * the first function to get to touch the default values. */
	engine_def_check();
	/* Attempt to get a functional reference (we need one anyway, but
	 * also, 'e' may be just a structural reference being passed in so
	 * this call may actually be the first). */
	if(!ENGINE_init(e))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DEFAULT_TYPE,
			ENGINE_R_INIT_FAILED);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	switch(t)
		{
	case ENGINE_TYPE_RSA:
		old = engine_def_rsa;
		engine_def_rsa = e; break;
	case ENGINE_TYPE_DSA:
		old = engine_def_dsa;
		engine_def_dsa = e; break;
	case ENGINE_TYPE_DH:
		old = engine_def_dh;
		engine_def_dh = e; break;
	case ENGINE_TYPE_RAND:
		old = engine_def_rand;
		engine_def_rand = e; break;
	case ENGINE_TYPE_BN_MOD_EXP:
		old = engine_def_bn_mod_exp;
		engine_def_bn_mod_exp = e; break;
	case ENGINE_TYPE_BN_MOD_EXP_CRT:
		old = engine_def_bn_mod_exp_crt;
		engine_def_bn_mod_exp_crt = e; break;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	/* If we've replaced a previous value, then we need to remove the
	 * functional reference we had. */
	if(old && !ENGINE_finish(old))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DEFAULT_TYPE,
			ENGINE_R_FINISH_FAILED);
		return 0;
		}
	return 1;
	}

int ENGINE_set_default_RSA(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_RSA, e);
	}

int ENGINE_set_default_DSA(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_DSA, e);
	}

int ENGINE_set_default_DH(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_DH, e);
	}

int ENGINE_set_default_RAND(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_RAND, e);
	}

int ENGINE_set_default_BN_mod_exp(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_BN_MOD_EXP, e);
	}

int ENGINE_set_default_BN_mod_exp_crt(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_BN_MOD_EXP_CRT, e);
	}

int ENGINE_set_default(ENGINE *e, unsigned int flags)
	{
	if((flags & ENGINE_METHOD_RSA) && e->rsa_meth &&
			!ENGINE_set_default_RSA(e))
		return 0;
	if((flags & ENGINE_METHOD_DSA) && e->dsa_meth &&
			!ENGINE_set_default_DSA(e))
		return 0;
	if((flags & ENGINE_METHOD_DH) && e->dh_meth &&
			!ENGINE_set_default_DH(e))
		return 0;
	if((flags & ENGINE_METHOD_RAND) && e->rand_meth &&
			!ENGINE_set_default_RAND(e))
		return 0;
	if((flags & ENGINE_METHOD_BN_MOD_EXP) && e->bn_mod_exp &&
			!ENGINE_set_default_BN_mod_exp(e))
		return 0;
	if((flags & ENGINE_METHOD_BN_MOD_EXP_CRT) && e->bn_mod_exp_crt &&
			!ENGINE_set_default_BN_mod_exp_crt(e))
		return 0;
	return 1;
	}

