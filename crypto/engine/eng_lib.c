/* crypto/engine/eng_lib.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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
#include "eng_int.h"
#include <openssl/engine.h>

/* These pointers each have their own "functional reference" when they
 * are non-NULL. Similarly, when they are retrieved by a call to
 * ENGINE_get_default_[RSA|DSA|...] the returned pointer is also a
 * reference and the caller is responsible for freeing that when they
 * are finished with it (with a call to ENGINE_finish() *NOT* just
 * ENGINE_free()!!!!!!). */
#ifndef OPENSSL_NO_RSA
static ENGINE *engine_def_rsa = NULL;
#endif
#ifndef OPENSSL_NO_DSA
static ENGINE *engine_def_dsa = NULL;
#endif
#ifndef OPENSSL_NO_DH
static ENGINE *engine_def_dh = NULL;
#endif
static ENGINE *engine_def_rand = NULL;
static ENGINE *engine_def_bn_mod_exp = NULL;
static ENGINE *engine_def_bn_mod_exp_crt = NULL;
/* A static "once-only" flag used to control if/when the above were
 * initialised to suitable start-up defaults. */
static int engine_def_flag = 0;

/* When querying a ENGINE-specific control command's 'description', this string
 * is used if the ENGINE_CMD_DEFN has cmd_desc set to NULL. */
static const char *int_no_description = "";

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
	engine_ref_debug(val, 0, 1)
	engine_ref_debug(val, 1, 1)
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
#ifndef OPENSSL_NO_RSA
		engine_def_check_util(&engine_def_rsa, e);
#endif
#ifndef OPENSSL_NO_DSA
		engine_def_check_util(&engine_def_dsa, e);
#endif
#ifndef OPENSSL_NO_DH
		engine_def_check_util(&engine_def_dh, e);
#endif
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
		to_return = e->init(e);
	if(to_return)
		{
		/* OK, we return a functional reference which is also a
		 * structural reference. */
		e->struct_ref++;
		e->funct_ref++;
		engine_ref_debug(e, 0, 1)
		engine_ref_debug(e, 1, 1)
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
	/* Reduce the functional reference count here so if it's the terminating
	 * case, we can release the lock safely and call the finish() handler
	 * without risk of a race. We get a race if we leave the count until
	 * after and something else is calling "finish" at the same time -
	 * there's a chance that both threads will together take the count from
	 * 2 to 0 without either calling finish(). */
	e->funct_ref--;
	engine_ref_debug(e, 1, -1)
	if((e->funct_ref == 0) && e->finish)
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		if(!(to_return = e->finish(e)))
			{
			ENGINEerr(ENGINE_F_ENGINE_FINISH,ENGINE_R_FINISH_FAILED);
			return 0;
			}
		}
	else
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
#ifdef REF_CHECK
	if(e->funct_ref < 0)
		{
		fprintf(stderr,"ENGINE_finish, bad functional reference count\n");
		abort();
		}
#endif
	/* Release the structural reference too */
	if(!ENGINE_free(e))
		{
		ENGINEerr(ENGINE_F_ENGINE_FINISH,ENGINE_R_FINISH_FAILED);
		return 0;
		}
	return to_return;
	}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
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
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	if (!e->load_privkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_NO_LOAD_FUNCTION);
		return 0;
		}
	pkey = e->load_privkey(e, key_id, ui_method, callback_data);
	if (!pkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PRIVATE_KEY,
			ENGINE_R_FAILED_LOADING_PRIVATE_KEY);
		return 0;
		}
	return pkey;
	}

EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
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
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	if (!e->load_pubkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_NO_LOAD_FUNCTION);
		return 0;
		}
	pkey = e->load_pubkey(e, key_id, ui_method, callback_data);
	if (!pkey)
		{
		ENGINEerr(ENGINE_F_ENGINE_LOAD_PUBLIC_KEY,
			ENGINE_R_FAILED_LOADING_PUBLIC_KEY);
		return 0;
		}
	return pkey;
	}

/* These internal functions handle 'CMD'-related control commands when the
 * ENGINE in question has asked us to take care of it (ie. the ENGINE did not
 * set the ENGINE_FLAGS_MANUAL_CMD_CTRL flag. */

static int int_ctrl_cmd_is_null(const ENGINE_CMD_DEFN *defn)
	{
	if((defn->cmd_num == 0) || (defn->cmd_name == NULL))
		return 1;
	return 0;
	}

static int int_ctrl_cmd_by_name(const ENGINE_CMD_DEFN *defn, const char *s)
	{
	int idx = 0;
	while(!int_ctrl_cmd_is_null(defn) && (strcmp(defn->cmd_name, s) != 0))
		{
		idx++;
		defn++;
		}
	if(int_ctrl_cmd_is_null(defn))
		/* The given name wasn't found */
		return -1;
	return idx;
	}

static int int_ctrl_cmd_by_num(const ENGINE_CMD_DEFN *defn, unsigned int num)
	{
	int idx = 0;
	/* NB: It is stipulated that 'cmd_defn' lists are ordered by cmd_num. So
	 * our searches don't need to take any longer than necessary. */
	while(!int_ctrl_cmd_is_null(defn) && (defn->cmd_num < num))
		{
		idx++;
		defn++;
		}
	if(defn->cmd_num == num)
		return idx;
	/* The given cmd_num wasn't found */
	return -1;
	}

static int int_ctrl_helper(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	int idx;
	char *s = (char *)p;
	/* Take care of the easy one first (eg. it requires no searches) */
	if(cmd == ENGINE_CTRL_GET_FIRST_CMD_TYPE)
		{
		if((e->cmd_defns == NULL) || int_ctrl_cmd_is_null(e->cmd_defns))
			return 0;
		return e->cmd_defns->cmd_num;
		}
	/* One or two commands require that "p" be a valid string buffer */
	if((cmd == ENGINE_CTRL_GET_CMD_FROM_NAME) ||
			(cmd == ENGINE_CTRL_GET_NAME_FROM_CMD) ||
			(cmd == ENGINE_CTRL_GET_DESC_FROM_CMD))
		{
		if(s == NULL)
			{
			ENGINEerr(ENGINE_F_INT_CTRL_HELPER,
				ERR_R_PASSED_NULL_PARAMETER);
			return -1;
			}
		}
	/* Now handle cmd_name -> cmd_num conversion */
	if(cmd == ENGINE_CTRL_GET_CMD_FROM_NAME)
		{
		if((e->cmd_defns == NULL) || ((idx = int_ctrl_cmd_by_name(
						e->cmd_defns, s)) < 0))
			{
			ENGINEerr(ENGINE_F_INT_CTRL_HELPER,
				ENGINE_R_INVALID_CMD_NAME);
			return -1;
			}
		return e->cmd_defns[idx].cmd_num;
		}
	/* For the rest of the commands, the 'long' argument must specify a
	 * valie command number - so we need to conduct a search. */
	if((e->cmd_defns == NULL) || ((idx = int_ctrl_cmd_by_num(e->cmd_defns,
					(unsigned int)i)) < 0))
		{
		ENGINEerr(ENGINE_F_INT_CTRL_HELPER,
			ENGINE_R_INVALID_CMD_NUMBER);
		return -1;
		}
	/* Now the logic splits depending on command type */
	switch(cmd)
		{
	case ENGINE_CTRL_GET_NEXT_CMD_TYPE:
		idx++;
		if(int_ctrl_cmd_is_null(e->cmd_defns + idx))
			/* end-of-list */
			return 0;
		else
			return e->cmd_defns[idx].cmd_num;
	case ENGINE_CTRL_GET_NAME_LEN_FROM_CMD:
		return strlen(e->cmd_defns[idx].cmd_name);
	case ENGINE_CTRL_GET_NAME_FROM_CMD:
		return sprintf(s, "%s", e->cmd_defns[idx].cmd_name);
	case ENGINE_CTRL_GET_DESC_LEN_FROM_CMD:
		if(e->cmd_defns[idx].cmd_desc)
			return strlen(e->cmd_defns[idx].cmd_desc);
		return strlen(int_no_description);
	case ENGINE_CTRL_GET_DESC_FROM_CMD:
		if(e->cmd_defns[idx].cmd_desc)
			return sprintf(s, "%s", e->cmd_defns[idx].cmd_desc);
		return sprintf(s, "%s", int_no_description);
	case ENGINE_CTRL_GET_CMD_FLAGS:
		return e->cmd_defns[idx].cmd_flags;
		}
	/* Shouldn't really be here ... */
	ENGINEerr(ENGINE_F_INT_CTRL_HELPER,ENGINE_R_INTERNAL_LIST_ERROR);
	return -1;
	}

int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	int ctrl_exists, ref_exists;
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	ref_exists = ((e->struct_ref > 0) ? 1 : 0);
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	ctrl_exists = ((e->ctrl == NULL) ? 0 : 1);
	if(!ref_exists)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ENGINE_R_NO_REFERENCE);
		return 0;
		}
	/* Intercept any "root-level" commands before trying to hand them on to
	 * ctrl() handlers. */
	switch(cmd)
		{
	case ENGINE_CTRL_HAS_CTRL_FUNCTION:
		return ctrl_exists;
	case ENGINE_CTRL_GET_FIRST_CMD_TYPE:
	case ENGINE_CTRL_GET_NEXT_CMD_TYPE:
	case ENGINE_CTRL_GET_CMD_FROM_NAME:
	case ENGINE_CTRL_GET_NAME_LEN_FROM_CMD:
	case ENGINE_CTRL_GET_NAME_FROM_CMD:
	case ENGINE_CTRL_GET_DESC_LEN_FROM_CMD:
	case ENGINE_CTRL_GET_DESC_FROM_CMD:
	case ENGINE_CTRL_GET_CMD_FLAGS:
		if(ctrl_exists && !(e->flags & ENGINE_FLAGS_MANUAL_CMD_CTRL))
			return int_ctrl_helper(e,cmd,i,p,f);
		if(!ctrl_exists)
			{
			ENGINEerr(ENGINE_F_ENGINE_CTRL,ENGINE_R_NO_CONTROL_FUNCTION);
			/* For these cmd-related functions, failure is indicated
			 * by a -1 return value (because 0 is used as a valid
			 * return in some places). */
			return -1;
			}
	default:
		break;
		}
	/* Anything else requires a ctrl() handler to exist. */
	if(!ctrl_exists)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL,ENGINE_R_NO_CONTROL_FUNCTION);
		return 0;
		}
	return e->ctrl(e, cmd, i, p, f);
	}

int ENGINE_cmd_is_executable(ENGINE *e, int cmd)
	{
	int flags;
	if((flags = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, cmd, NULL, NULL)) < 0)
		{
		ENGINEerr(ENGINE_F_ENGINE_CMD_IS_EXECUTABLE,
			ENGINE_R_INVALID_CMD_NUMBER);
		return 0;
		}
	if(!(flags & ENGINE_CMD_FLAG_NO_INPUT) &&
			!(flags & ENGINE_CMD_FLAG_NUMERIC) &&
			!(flags & ENGINE_CMD_FLAG_STRING))
		return 0;
	return 1;
	}

int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
        long i, void *p, void (*f)(), int cmd_optional)
        {
	int num;

	if((e == NULL) || (cmd_name == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if((e->ctrl == NULL) || ((num = ENGINE_ctrl(e,
					ENGINE_CTRL_GET_CMD_FROM_NAME,
					0, (void *)cmd_name, NULL)) <= 0))
		{
		/* If the command didn't *have* to be supported, we fake
		 * success. This allows certain settings to be specified for
		 * multiple ENGINEs and only require a change of ENGINE id
		 * (without having to selectively apply settings). Eg. changing
		 * from a hardware device back to the regular software ENGINE
		 * without editing the config file, etc. */
		if(cmd_optional)
			{
			ERR_clear_error();
			return 1;
			}
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD,
			ENGINE_R_INVALID_CMD_NAME);
		return 0;
		}
	/* Force the result of the control command to 0 or 1, for the reasons
	 * mentioned before. */
        if (ENGINE_ctrl(e, num, i, p, f))
                return 1;
        return 0;
        }

int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
				int cmd_optional)
	{
	int num, flags;
	long l;
	char *ptr;
	if((e == NULL) || (cmd_name == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if((e->ctrl == NULL) || ((num = ENGINE_ctrl(e,
					ENGINE_CTRL_GET_CMD_FROM_NAME,
					0, (void *)cmd_name, NULL)) <= 0))
		{
		/* If the command didn't *have* to be supported, we fake
		 * success. This allows certain settings to be specified for
		 * multiple ENGINEs and only require a change of ENGINE id
		 * (without having to selectively apply settings). Eg. changing
		 * from a hardware device back to the regular software ENGINE
		 * without editing the config file, etc. */
		if(cmd_optional)
			{
			ERR_clear_error();
			return 1;
			}
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_INVALID_CMD_NAME);
		return 0;
		}
	if(!ENGINE_cmd_is_executable(e, num))
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_CMD_NOT_EXECUTABLE);
		return 0;
		}
	if((flags = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, num, NULL, NULL)) < 0)
		{
		/* Shouldn't happen, given that ENGINE_cmd_is_executable()
		 * returned success. */
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_INTERNAL_LIST_ERROR);
		return 0;
		}
	/* If the command takes no input, there must be no input. And vice
	 * versa. */
	if(flags & ENGINE_CMD_FLAG_NO_INPUT)
		{
		if(arg != NULL)
			{
			ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
				ENGINE_R_COMMAND_TAKES_NO_INPUT);
			return 0;
			}
		/* We deliberately force the result of ENGINE_ctrl() to 0 or 1
		 * rather than returning it as "return data". This is to ensure
		 * usage of these commands is consistent across applications and
		 * that certain applications don't understand it one way, and
		 * others another. */
		if(ENGINE_ctrl(e, num, 0, (void *)arg, NULL))
			return 1;
		return 0;
		}
	/* So, we require input */
	if(arg == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_COMMAND_TAKES_INPUT);
		return 0;
		}
	/* If it takes string input, that's easy */
	if(flags & ENGINE_CMD_FLAG_STRING)
		{
		/* Same explanation as above */
		if(ENGINE_ctrl(e, num, 0, (void *)arg, NULL))
			return 1;
		return 0;
		}
	/* If it doesn't take numeric either, then it is unsupported for use in
	 * a config-setting situation, which is what this function is for. This
	 * should never happen though, because ENGINE_cmd_is_executable() was
	 * used. */
	if(!(flags & ENGINE_CMD_FLAG_NUMERIC))
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_INTERNAL_LIST_ERROR);
		return 0;
		}
	l = strtol(arg, &ptr, 10);
	if((arg == ptr) || (*ptr != '\0'))
		{
		ENGINEerr(ENGINE_F_ENGINE_CTRL_CMD_STRING,
			ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER);
		return 0;
		}
	/* Force the result of the control command to 0 or 1, for the reasons
	 * mentioned before. */
	if(ENGINE_ctrl(e, num, l, NULL, NULL))
		return 1;
	return 0;
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
#ifndef OPENSSL_NO_RSA
	case ENGINE_TYPE_RSA:
		ret = engine_def_rsa; break;
#endif
#ifndef OPENSSL_NO_DSA
	case ENGINE_TYPE_DSA:
		ret = engine_def_dsa; break;
#endif
#ifndef OPENSSL_NO_DH
	case ENGINE_TYPE_DH:
		ret = engine_def_dh; break;
#endif
	case ENGINE_TYPE_RAND:
		ret = engine_def_rand; break;
	case ENGINE_TYPE_BN_MOD_EXP:
		ret = engine_def_bn_mod_exp; break;
	case ENGINE_TYPE_BN_MOD_EXP_CRT:
		ret = engine_def_bn_mod_exp_crt; break;
	default:
		break;
		}
	/* Unforunately we can't do this work outside the lock with a
	 * call to ENGINE_init() because that would leave a race
	 * condition open. */
	if(ret)
		{
		ret->struct_ref++;
		ret->funct_ref++;
		engine_ref_debug(ret, 0, 1)
		engine_ref_debug(ret, 1, 1)
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return ret;
	}

#ifndef OPENSSL_NO_RSA
ENGINE *ENGINE_get_default_RSA(void)
	{
	return engine_get_default_type(ENGINE_TYPE_RSA);
	}
#endif

#ifndef OPENSSL_NO_DSA
ENGINE *ENGINE_get_default_DSA(void)
	{
	return engine_get_default_type(ENGINE_TYPE_DSA);
	}
#endif

#ifndef OPENSSL_NO_DH
ENGINE *ENGINE_get_default_DH(void)
	{
	return engine_get_default_type(ENGINE_TYPE_DH);
	}
#endif

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

	/* engine_def_check is lean and mean and won't replace any
	 * prior default engines ... so we must ensure that it is always
	 * the first function to get to touch the default values. */
	engine_def_check();
	/* Attempt to get a functional reference (we need one anyway, but
	 * also, 'e' may be just a structural reference being passed in so
	 * this call may actually be the first). */
	if(e && !ENGINE_init(e))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DEFAULT_TYPE,
			ENGINE_R_INIT_FAILED);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	switch(t)
		{
#ifndef OPENSSL_NO_RSA
	case ENGINE_TYPE_RSA:
		old = engine_def_rsa;
		engine_def_rsa = e; break;
#endif
#ifndef OPENSSL_NO_DSA
	case ENGINE_TYPE_DSA:
		old = engine_def_dsa;
		engine_def_dsa = e; break;
#endif
#ifndef OPENSSL_NO_DH
	case ENGINE_TYPE_DH:
		old = engine_def_dh;
		engine_def_dh = e; break;
#endif
	case ENGINE_TYPE_RAND:
		old = engine_def_rand;
		engine_def_rand = e; break;
	case ENGINE_TYPE_BN_MOD_EXP:
		old = engine_def_bn_mod_exp;
		engine_def_bn_mod_exp = e; break;
	case ENGINE_TYPE_BN_MOD_EXP_CRT:
		old = engine_def_bn_mod_exp_crt;
		engine_def_bn_mod_exp_crt = e; break;
	default:
		break;
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

#ifndef OPENSSL_NO_RSA
int ENGINE_set_default_RSA(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_RSA, e);
	}
#endif

#ifndef OPENSSL_NO_DSA
int ENGINE_set_default_DSA(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_DSA, e);
	}
#endif

#ifndef OPENSSL_NO_DH
int ENGINE_set_default_DH(ENGINE *e)
	{
	return engine_set_default_type(ENGINE_TYPE_DH, e);
	}
#endif

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
#ifndef OPENSSL_NO_RSA
	if((flags & ENGINE_METHOD_RSA) && e->rsa_meth &&
			!ENGINE_set_default_RSA(e))
		return 0;
#endif
#ifndef OPENSSL_NO_DSA
	if((flags & ENGINE_METHOD_DSA) && e->dsa_meth &&
			!ENGINE_set_default_DSA(e))
		return 0;
#endif
#ifndef OPENSSL_NO_DH
	if((flags & ENGINE_METHOD_DH) && e->dh_meth &&
			!ENGINE_set_default_DH(e))
		return 0;
#endif
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

int ENGINE_clear_defaults(void)
	{
	/* If the defaults haven't even been set yet, don't bother. Any kind of
	 * "cleanup" has a kind of implicit race-condition if another thread is
	 * trying to keep going, so we don't address that with locking. The
	 * first ENGINE_set_default_*** call will actually *create* a standard
	 * set of default ENGINEs (including init() and functional reference
	 * counts aplenty) before the rest of this function undoes them all. So
	 * save some hassle ... */
	if(!engine_def_flag)
		return 1;
	if((0 == 1) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_default_RSA(NULL) ||
#endif
#ifndef OPENSSL_NO_DSA
			!ENGINE_set_default_DSA(NULL) ||
#endif
#ifndef OPENSSL_NO_DH
			!ENGINE_set_default_DH(NULL) ||
#endif
			!ENGINE_set_default_RAND(NULL) ||
			!ENGINE_set_default_BN_mod_exp(NULL) ||
			!ENGINE_set_default_BN_mod_exp_crt(NULL) ||
			!RAND_set_rand_method(NULL))
		return 0;
	return 1;
	}

