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
	/* remove our structural reference. */
	e->struct_ref--;
	return 1;
	}

/* This check always takes place with CRYPTO_LOCK_ENGINE locked up
 * so we're synchronised, but we can't call anything that tries to
 * lock it again! :-) NB: For convenience (and code-clarity) we
 * don't output errors for failures of the engine_list_add function
 * as it will generate errors itself. */
static int engine_internal_check(void)
	{
	if(engine_list_flag)
		return 1;
	/* This is our first time up, we need to populate the list
	 * with our statically compiled-in engines. */
	if(!engine_list_add(ENGINE_openssl()))
		return 0;
#ifndef NO_HW
#ifndef NO_HW_CSWIFT
	if(!engine_list_add(ENGINE_cswift()))
		return 0;
#endif /* !NO_HW_CSWIFT */
#ifndef NO_HW_NCIPHER
	if(!engine_list_add(ENGINE_ncipher()))
		return 0;
#endif /* !NO_HW_NCIPHER */
#ifndef NO_HW_ATALLA
	if(!engine_list_add(ENGINE_atalla()))
		return 0;
#endif /* !NO_HW_ATALLA */
#endif /* !NO_HW */
	engine_list_flag = 1;
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
			ret->struct_ref++;
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
			ret->struct_ref++;
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
	e->struct_ref--;
	if(ret)
		ret->struct_ref++;
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
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
	e->struct_ref--;
	if(ret)
		ret->struct_ref++;
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
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
	ENGINE *iterator = NULL;
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
			/* We need to return a structural reference */
			iterator->struct_ref++;
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_ENGINE);
	if(iterator == NULL)
		ENGINEerr(ENGINE_F_ENGINE_BY_ID,
			ENGINE_R_NO_SUCH_ENGINE);
	return iterator;
	}

/* As per the comments in engine.h, it is generally better all round
 * if the ENGINE structure is allocated within this framework. */
#if 0
int ENGINE_get_struct_size(void)
	{
	return sizeof(ENGINE);
	}

ENGINE *ENGINE_new(ENGINE *e)
	{
	ENGINE *ret;

	if(e == NULL)
		{
		ret = (ENGINE *)(OPENSSL_malloc(sizeof(ENGINE));
		if(ret == NULL)
			{
			ENGINEerr(ENGINE_F_ENGINE_NEW,
				ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		}
	else
		ret = e;
	memset(ret, 0, sizeof(ENGINE));
	if(e)
		ret->flags = ENGINE_FLAGS_MALLOCED;
	ret->struct_ref = 1;
	return ret;
	}
#else
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
	ret->flags = ENGINE_FLAGS_MALLOCED;
	ret->struct_ref = 1;
	return ret;
	}
#endif

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
#ifdef REF_PRINT
	REF_PRINT("ENGINE",e);
#endif
	if (i > 0) return 1;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ENGINE_free, bad reference count\n");
		abort();
		}
#endif
	if(e->flags & ENGINE_FLAGS_MALLOCED)
		OPENSSL_free(e);
	return 1;
	}

int ENGINE_set_id(ENGINE *e, const char *id)
	{
	if((e == NULL) || (id == NULL))
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
	if((e == NULL) || (name == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_NAME,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->name = name;
	return 1;
	}

int ENGINE_set_RSA(ENGINE *e, RSA_METHOD *rsa_meth)
	{
	if((e == NULL) || (rsa_meth == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->rsa_meth = rsa_meth;
	return 1;
	}

int ENGINE_set_DSA(ENGINE *e, DSA_METHOD *dsa_meth)
	{
	if((e == NULL) || (dsa_meth == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->dsa_meth = dsa_meth;
	return 1;
	}

int ENGINE_set_DH(ENGINE *e, DH_METHOD *dh_meth)
	{
	if((e == NULL) || (dh_meth == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_DH,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->dh_meth = dh_meth;
	return 1;
	}

int ENGINE_set_RAND(ENGINE *e, RAND_METHOD *rand_meth)
	{
	if((e == NULL) || (rand_meth == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_RAND,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->rand_meth = rand_meth;
	return 1;
	}

int ENGINE_set_BN_mod_exp(ENGINE *e, BN_MOD_EXP bn_mod_exp)
	{
	if((e == NULL) || (bn_mod_exp == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_BN_MOD_EXP,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->bn_mod_exp = bn_mod_exp;
	return 1;
	}

int ENGINE_set_BN_mod_exp_crt(ENGINE *e, BN_MOD_EXP_CRT bn_mod_exp_crt)
	{
	if((e == NULL) || (bn_mod_exp_crt == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_BN_MOD_EXP_CRT,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->bn_mod_exp_crt = bn_mod_exp_crt;
	return 1;
	}

int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f)
	{
	if((e == NULL) || (init_f == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_INIT_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->init = init_f;
	return 1;
	}

int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f)
	{
	if((e == NULL) || (finish_f == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_FINISH_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->finish = finish_f;
	return 1;
	}

int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f)
	{
	if((e == NULL) || (ctrl_f == NULL))
		{
		ENGINEerr(ENGINE_F_ENGINE_SET_CTRL_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	e->ctrl = ctrl_f;
	return 1;
	}

const char *ENGINE_get_id(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_ID,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	return e->id;
	}

const char *ENGINE_get_name(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_NAME,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	return e->name;
	}

RSA_METHOD *ENGINE_get_RSA(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->rsa_meth;
	}

DSA_METHOD *ENGINE_get_DSA(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_DSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->dsa_meth;
	}

DH_METHOD *ENGINE_get_DH(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_DH,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->dh_meth;
	}

RAND_METHOD *ENGINE_get_RAND(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_RAND,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->rand_meth;
	}

BN_MOD_EXP ENGINE_get_BN_mod_exp(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_BN_MOD_EXP,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->bn_mod_exp;
	}

BN_MOD_EXP_CRT ENGINE_get_BN_mod_exp_crt(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_BN_MOD_EXP_CRT,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->bn_mod_exp_crt;
	}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_INIT_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->init;
	}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_FINISH_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->finish;
	}

ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(ENGINE *e)
	{
	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_GET_CTRL_FUNCTION,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	return e->ctrl;
	}

