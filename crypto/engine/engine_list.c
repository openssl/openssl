/* crypto/engine/engine_list.c */
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

/* Weird "ex_data" handling. Some have suggested there's some problems with the
 * CRYPTO_EX_DATA code (or model), but for now I'm implementing it exactly as
 * it's done in crypto/rsa/. That way the usage and documentation of that can be
 * used to assist here, and any changes or fixes made there should similarly map
 * over here quite straightforwardly. */
static int engine_ex_data_num = 0;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *engine_ex_data_stack = NULL;

/* The linked-list of pointers to engine types. engine_list_head
 * incorporates an implicit structural reference but engine_list_tail
 * does not - the latter is a computational niceity and only points
 * to something that is already pointed to by its predecessor in the
 * list (or engine_list_head itself). In the same way, the use of the
 * "prev" pointer in each ENGINE is to save excessive list iteration,
 * it doesn't correspond to an extra structural reference. Hence,
 * engine_list_head, and each non-null "next" pointer account for
 * the list itself assuming exactly 1 structural reference on each
 * list member. */
static ENGINE *engine_list_head = NULL;
static ENGINE *engine_list_tail = NULL;
/* A boolean switch, used to ensure we only initialise once. This
 * is needed because the engine list may genuinely become empty during
 * use (so we can't use engine_list_head as an indicator for example. */
static int engine_list_flag = 0;
static int ENGINE_free_nolock(ENGINE *e);

/* These static functions starting with a lower case "engine_" always
 * take place when CRYPTO_LOCK_ENGINE has been locked up. */
static int engine_list_add(ENGINE *e)
	{
	int conflict = 0;
	ENGINE *iterator = NULL;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_LIST_ADD,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	iterator = engine_list_head;
	while(iterator && !conflict)
		{
		conflict = (strcmp(iterator->id, e->id) == 0);
		iterator = iterator->next;
		}
	if(conflict)
		{
		ENGINEerr(ENGINE_F_ENGINE_LIST_ADD,
			ENGINE_R_CONFLICTING_ENGINE_ID);
		return 0;
		}
	if(engine_list_head == NULL)
		{
		/* We are adding to an empty list. */
		if(engine_list_tail)
			{
			ENGINEerr(ENGINE_F_ENGINE_LIST_ADD,
				ENGINE_R_INTERNAL_LIST_ERROR);
			return 0;
			}
		engine_list_head = e;
		e->prev = NULL;
		}
	else
		{
		/* We are adding to the tail of an existing list. */
		if((engine_list_tail == NULL) ||
				(engine_list_tail->next != NULL))
			{
			ENGINEerr(ENGINE_F_ENGINE_LIST_ADD,
				ENGINE_R_INTERNAL_LIST_ERROR);
			return 0;
			}
		engine_list_tail->next = e;
		e->prev = engine_list_tail;
		}
	/* Having the engine in the list assumes a structural
	 * reference. */
	e->struct_ref++;
	engine_ref_debug(e, 0, 1)
	/* However it came to be, e is the last item in the list. */
	engine_list_tail = e;
	e->next = NULL;
	return 1;
	}

static int engine_list_remove(ENGINE *e)
	{
	ENGINE *iterator;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_LIST_REMOVE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	/* We need to check that e is in our linked list! */
	iterator = engine_list_head;
	while(iterator && (iterator != e))
		iterator = iterator->next;
	if(iterator == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_LIST_REMOVE,
			ENGINE_R_ENGINE_IS_NOT_IN_LIST);
		return 0;
		}
	/* un-link e from the chain. */
	if(e->next)
		e->next->prev = e->prev;
	if(e->prev)
		e->prev->next = e->next;
	/* Correct our head/tail if necessary. */
	if(engine_list_head == e)
		engine_list_head = e->next;
	if(engine_list_tail == e)
		engine_list_tail = e->prev;
	ENGINE_free_nolock(e);
	return 1;
	}

/* This check always takes place with CRYPTO_LOCK_ENGINE locked up
 * so we're synchronised, but we can't call anything that tries to
 * lock it again! :-) NB: For convenience (and code-clarity) we
 * don't output errors for failures of the engine_list_add function
 * as it will generate errors itself. */
static int engine_internal_check(void)
	{
	int toret = 1;
	ENGINE *def_engine;
	if(engine_list_flag)
		return 1;
	/* This is our first time up, we need to populate the list
	 * with our statically compiled-in engines. */
	def_engine = ENGINE_openssl();
	if(!engine_list_add(def_engine))
		toret = 0;
	else
		engine_list_flag = 1;
	ENGINE_free_nolock(def_engine);
	return 1;
	}

/* Get the first/last "ENGINE" type available. */
ENGINE *ENGINE_get_first(void)
	{
	ENGINE *ret = NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ENGINE);
	if(engine_internal_check())
		{
		ret = engine_list_head;
		if(ret)
			{
			ret->struct_ref++;
			engine_ref_debug(ret, 0, 1)
			}
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	return ret;
	}
ENGINE *ENGINE_get_last(void)
	{
	ENGINE *ret = NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ENGINE);
	if(engine_internal_check())
		{
		ret = engine_list_tail;
		if(ret)
			{
			ret->struct_ref++;
			engine_ref_debug(ret, 0, 1)
			}
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	return ret;
	}

/* Iterate to the next/previous "ENGINE" type (NULL = end of the list). */
ENGINE *ENGINE_get_next(ENGINE *e)
	{
	ENGINE *ret = NULL;
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_NEXT,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_r_lock(CRYPTO_LOCK_ENGINE);
	ret = e->next;
	if(ret)
		{
		/* Return a valid structural refernce to the next ENGINE */
		ret->struct_ref++;
		engine_ref_debug(ret, 0, 1)
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	/* Release the structural reference to the previous ENGINE */
	ENGINE_free(e);
	return ret;
	}
ENGINE *ENGINE_get_prev(ENGINE *e)
	{
	ENGINE *ret = NULL;
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_PREV,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_r_lock(CRYPTO_LOCK_ENGINE);
	ret = e->prev;
	if(ret)
		{
		/* Return a valid structural reference to the next ENGINE */
		ret->struct_ref++;
		engine_ref_debug(ret, 0, 1)
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	/* Release the structural reference to the previous ENGINE */
	ENGINE_free(e);
	return ret;
	}

/* Add another "ENGINE" type into the list. */
int ENGINE_add(ENGINE *e)
	{
	int to_return = 1;
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_ADD,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if((e->id == NULL) || (e->name == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_ADD,
			ENGINE_R_ID_OR_NAME_MISSING);
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(!engine_internal_check() || !engine_list_add(e))
		{
		ENGINEerr(ENGINE_F_ENGINE_ADD,
			ENGINE_R_INTERNAL_LIST_ERROR);
		to_return = 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return to_return;
	}

/* Remove an existing "ENGINE" type from the array. */
int ENGINE_remove(ENGINE *e)
	{
	int to_return = 1;
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_REMOVE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(!engine_internal_check() || !engine_list_remove(e))
		{
		ENGINEerr(ENGINE_F_ENGINE_REMOVE,
			ENGINE_R_INTERNAL_LIST_ERROR);
		to_return = 0;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return to_return;
	}

ENGINE *ENGINE_by_id(const char *id)
	{
	ENGINE *iterator = NULL, *cp = NULL;
	if(id == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_BY_ID,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	CRYPTO_r_lock(CRYPTO_LOCK_ENGINE);
	if(!engine_internal_check())
		ENGINEerr(ENGINE_F_ENGINE_BY_ID,
			ENGINE_R_INTERNAL_LIST_ERROR);
	else
		{
		iterator = engine_list_head;
		while(iterator && (strcmp(id, iterator->id) != 0))
			iterator = iterator->next;
		if(iterator)
			{
			/* We need to return a structural reference. If this is
			 * a "dynamic" ENGINE type, make a duplicate - otherwise
			 * increment the existing ENGINE's reference count. */
			if(iterator->flags & ENGINE_FLAGS_BY_ID_COPY)
				{
				cp = ENGINE_new();
				if(!cp)
					iterator = NULL;
				else
					{
					ENGINE_cpy(cp, iterator);
					iterator = cp;
					}
				}
			else
				{
				iterator->struct_ref++;
				engine_ref_debug(iterator, 0, 1)
				}
			}
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	if(iterator == NULL)
		ENGINEerr(ENGINE_F_ENGINE_BY_ID,
			ENGINE_R_NO_SUCH_ENGINE);
	return iterator;
	}

ENGINE *ENGINE_new(void)
	{
	ENGINE *ret;

	ret = (ENGINE *)OPENSSL_malloc(sizeof(ENGINE));
	if(ret == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	memset(ret, 0, sizeof(ENGINE));
	ret->struct_ref = 1;
	engine_ref_debug(ret, 0, 1)
	CRYPTO_new_ex_data(engine_ex_data_stack, ret, &ret->ex_data);
	return ret;
	}

int ENGINE_free(ENGINE *e)
	{
	int i;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_FREE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	i = CRYPTO_add(&e->struct_ref,-1,CRYPTO_LOCK_ENGINE);
	engine_ref_debug(e, 0, -1)
	if (i > 0) return 1;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ENGINE_free, bad structural reference count\n");
		abort();
		}
#endif
	CRYPTO_free_ex_data(engine_ex_data_stack, e, &e->ex_data);
	OPENSSL_free(e);
	return 1;
	}

static int ENGINE_free_nolock(ENGINE *e)
	{
	int i;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_FREE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	
	i=--e->struct_ref;
	engine_ref_debug(e, 0, -1)
	if (i > 0) return 1;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ENGINE_free, bad structural reference count\n");
		abort();
		}
#endif
	CRYPTO_free_ex_data(engine_ex_data_stack, e, &e->ex_data);
	OPENSSL_free(e);
	return 1;
	}

int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
		CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
	{
	if(CRYPTO_get_ex_new_index(engine_ex_data_num, &engine_ex_data_stack,
			argl, argp, new_func, dup_func, free_func) < 0)
		return -1;
	return (engine_ex_data_num++);
	}

int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg)
	{
	return(CRYPTO_set_ex_data(&e->ex_data, idx, arg));
	}

void *ENGINE_get_ex_data(const ENGINE *e, int idx)
	{
	return(CRYPTO_get_ex_data(&e->ex_data, idx));
	}

void ENGINE_cleanup(void)
	{
	ENGINE *iterator = engine_list_head;

	while(iterator != NULL)
		{
		ENGINE_remove(iterator);
		iterator = engine_list_head;
		}
	engine_list_flag = 0;
	/* Also unset any "default" ENGINEs that may have been set up (a default
	 * constitutes a functional reference on an ENGINE and there's one for
	 * each algorithm). */
	ENGINE_clear_defaults();
	return;
	}

int ENGINE_set_id(ENGINE *e, const char *id)
	{
	if(id == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_ID,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->id = id;
	return 1;
	}

int ENGINE_set_name(ENGINE *e, const char *name)
	{
	if(name == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_NAME,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->name = name;
	return 1;
	}

int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth)
	{
#ifndef OPENSSL_NO_RSA
	e->rsa_meth = rsa_meth;
	return 1;
#else
	return 0;
#endif
	}

int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth)
	{
#ifndef OPENSSL_NO_DSA
	e->dsa_meth = dsa_meth;
	return 1;
#else
	return 0;
#endif
	}

int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth)
	{
#ifndef OPENSSL_NO_DH
	e->dh_meth = dh_meth;
	return 1;
#else
	return 0;
#endif
	}

int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth)
	{
	e->rand_meth = rand_meth;
	return 1;
	}

int ENGINE_set_BN_mod_exp(ENGINE *e, BN_MOD_EXP bn_mod_exp)
	{
	e->bn_mod_exp = bn_mod_exp;
	return 1;
	}

int ENGINE_set_BN_mod_exp_crt(ENGINE *e, BN_MOD_EXP_CRT bn_mod_exp_crt)
	{
	e->bn_mod_exp_crt = bn_mod_exp_crt;
	return 1;
	}

int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f)
	{
	e->init = init_f;
	return 1;
	}

int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f)
	{
	e->finish = finish_f;
	return 1;
	}

int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f)
	{
	e->ctrl = ctrl_f;
	return 1;
	}

int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f)
	{
	e->load_privkey = loadpriv_f;
	return 1;
	}

int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f)
	{
	e->load_pubkey = loadpub_f;
	return 1;
	}

int ENGINE_set_flags(ENGINE *e, int flags)
	{
	e->flags = flags;
	return 1;
	}

int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns)
	{
	e->cmd_defns = defns;
	return 1;
	}

int ENGINE_cpy(ENGINE *dest, const ENGINE *src)
	{
	if(ENGINE_set_id(dest, ENGINE_get_id(src)) &&
			ENGINE_set_name(dest, ENGINE_get_name(src)) &&
#ifndef OPENSSL_NO_RSA
			ENGINE_set_RSA(dest, ENGINE_get_RSA(src)) &&
#endif
#ifndef OPENSSL_NO_RSA
			ENGINE_set_DSA(dest, ENGINE_get_DSA(src)) &&
#endif
#ifndef OPENSSL_NO_RSA
			ENGINE_set_DH(dest, ENGINE_get_DH(src)) &&
#endif
			ENGINE_set_RAND(dest, ENGINE_get_RAND(src)) &&
			ENGINE_set_BN_mod_exp(dest,
					ENGINE_get_BN_mod_exp(src)) &&
			ENGINE_set_BN_mod_exp_crt(dest,
					ENGINE_get_BN_mod_exp_crt(src)) &&
			ENGINE_set_init_function(dest,
					ENGINE_get_init_function(src)) &&
			ENGINE_set_finish_function(dest,
					ENGINE_get_finish_function(src)) &&
			ENGINE_set_ctrl_function(dest,
					ENGINE_get_ctrl_function(src)) &&
			ENGINE_set_load_privkey_function(dest,
					ENGINE_get_load_privkey_function(src)) &&
			ENGINE_set_load_pubkey_function(dest,
					ENGINE_get_load_pubkey_function(src)) &&
			ENGINE_set_flags(dest, ENGINE_get_flags(src)) &&
			ENGINE_set_cmd_defns(dest, ENGINE_get_cmd_defns(src)))
		return 1;
	return 0;
	}

const char *ENGINE_get_id(const ENGINE *e)
	{
	return e->id;
	}

const char *ENGINE_get_name(const ENGINE *e)
	{
	return e->name;
	}

const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e)
	{
	return e->rsa_meth;
	}

const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e)
	{
	return e->dsa_meth;
	}

const DH_METHOD *ENGINE_get_DH(const ENGINE *e)
	{
	return e->dh_meth;
	}

const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e)
	{
	return e->rand_meth;
	}

BN_MOD_EXP ENGINE_get_BN_mod_exp(const ENGINE *e)
	{
	return e->bn_mod_exp;
	}

BN_MOD_EXP_CRT ENGINE_get_BN_mod_exp_crt(const ENGINE *e)
	{
	return e->bn_mod_exp_crt;
	}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e)
	{
	return e->init;
	}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e)
	{
	return e->finish;
	}

ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e)
	{
	return e->ctrl;
	}

ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e)
	{
	return e->load_privkey;
	}

ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e)
	{
	return e->load_pubkey;
	}

int ENGINE_get_flags(const ENGINE *e)
	{
	return e->flags;
	}

const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e)
	{
	return e->cmd_defns;
	}
