/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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

#include <openssl/evp.h>
#include <openssl/engine.h>
#include "eng_int.h"

/* This is the type of item in the 'implementation' table. Each 'nid' hashes to
 * a (potentially NULL) ENGINE_PILE structure which contains a stack of ENGINE*
 * pointers. These pointers aren't references, because they're inserted and
 * removed during ENGINE creation and ENGINE destruction. They point to ENGINEs
 * that *exist* (ie. have a structural reference count greater than zero) rather
 * than ENGINEs that are *functional*. Each pointer in those stacks are to
 * ENGINEs that implements the algorithm corresponding to each 'nid'. */

/* The type of the items in the table */
typedef struct st_engine_pile
	{
	/* The 'nid' of the algorithm/mode this ENGINE_PILE structure represents
	 * */
	int nid;
	/* A stack of ENGINE pointers for ENGINEs that support this
	 * algorithm/mode. In the event that 'funct' is NULL, the first entry in
	 * this stack that initialises will be set as 'funct' and assumed as the
	 * default for operations of this type. */
	STACK_OF(ENGINE) *sk;
	/* The default ENGINE to perform this algorithm/mode. */
	ENGINE *funct;
	/* This value optimises engine_table_select(). If it is called it sets
	 * this value to 1. Any changes to this ENGINE_PILE resets it to zero.
	 * As such, no ENGINE_init() thrashing is done unless ENGINEs
	 * continually register (and/or unregister). */
	int uptodate;
	} ENGINE_PILE;

/* The type of the hash table of ENGINE_PILE structures such that each are
 * unique and keyed by the 'nid' value. */
struct st_engine_table
	{
	LHASH piles;
	}; /* ENGINE_TABLE */

/* This value stores global options controlling behaviour of (mostly) the
 * engine_table_select() function. It's a bitmask of flag values of the form
 * ENGINE_TABLE_FLAG_*** (as defined in engine.h) and is controlled by the
 * ENGINE_[get|set]_table_flags() function. */
static unsigned int table_flags = 0;

/* API function manipulating 'table_flags' */
unsigned int ENGINE_get_table_flags(void)
	{
	return table_flags;
	}
void ENGINE_set_table_flags(unsigned int flags)
	{
	table_flags = flags;
	}

/* Internal functions for the "piles" hash table */
static unsigned long engine_pile_hash(const ENGINE_PILE *c)
	{
	return c->nid;
	}
static int engine_pile_cmp(const ENGINE_PILE *a, const ENGINE_PILE *b)
	{
	return a->nid - b->nid;
	}
static IMPLEMENT_LHASH_HASH_FN(engine_pile_hash, const ENGINE_PILE *)
static IMPLEMENT_LHASH_COMP_FN(engine_pile_cmp, const ENGINE_PILE *)
static int int_table_check(ENGINE_TABLE **t, int create)
	{
	LHASH *lh;
	if(*t)
		return 1;
	if(!create)
		return 0;
	if((lh = lh_new(LHASH_HASH_FN(engine_pile_hash),
			LHASH_COMP_FN(engine_pile_cmp))) == NULL)
		return 0;
	*t = (ENGINE_TABLE *)lh;
	return 1;
	}

/* Privately exposed (via eng_int.h) functions for adding and/or removing
 * ENGINEs from the implementation table */
int engine_table_register(ENGINE_TABLE **table, ENGINE_CLEANUP_CB *cleanup,
		ENGINE *e, const int *nids, int num_nids, int setdefault)
	{
	int ret = 0, added = 0;
	ENGINE_PILE tmplate, *fnd;
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(!(*table))
		added = 1;
	if(!int_table_check(table, 1))
		goto end;
	if(added)
		/* The cleanup callback needs to be added */
		engine_cleanup_add_first(cleanup);
	while(num_nids--)
		{
		tmplate.nid = *nids;
		fnd = lh_retrieve(&(*table)->piles, &tmplate);
		if(!fnd)
			{
			fnd = OPENSSL_malloc(sizeof(ENGINE_PILE));
			if(!fnd)
				goto end;
			fnd->uptodate = 1;
			fnd->nid = *nids;
			fnd->sk = sk_ENGINE_new_null();
			if(!fnd->sk)
				{
				OPENSSL_free(fnd);
				goto end;
				}
			fnd->funct= NULL;
			lh_insert(&(*table)->piles, fnd);
			}
		/* A registration shouldn't add duplciate entries */
		sk_ENGINE_delete_ptr(fnd->sk, e);
		/* if 'setdefault', this ENGINE goes to the head of the list */
		if(!sk_ENGINE_push(fnd->sk, e))
			goto end;
		/* "touch" this ENGINE_PILE */
		fnd->uptodate = 0;
		if(setdefault)
			{
			if(!engine_unlocked_init(e))
				{
				ENGINEerr(ENGINE_F_ENGINE_TABLE_REGISTER,
						ENGINE_R_INIT_FAILED);
				goto end;
				}
			if(fnd->funct)
				engine_unlocked_finish(fnd->funct, 0);
			fnd->funct = e;
			}
		nids++;
		}
	ret = 1;
end:
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	return ret;
	}
static void int_unregister_cb(ENGINE_PILE *pile, ENGINE *e)
	{
	int n;
	/* Iterate the 'c->sk' stack removing any occurance of 'e' */
	while((n = sk_ENGINE_find(pile->sk, e)) >= 0)
		{
		sk_ENGINE_delete(pile->sk, n);
		/* "touch" this ENGINE_CIPHER */
		pile->uptodate = 0;
		}
	if(pile->funct == e)
		{
		engine_unlocked_finish(e, 0);
		pile->funct = NULL;
		}
	}
static IMPLEMENT_LHASH_DOALL_ARG_FN(int_unregister_cb,ENGINE_PILE *,ENGINE *)
void engine_table_unregister(ENGINE_TABLE **table, ENGINE *e)
	{
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(int_table_check(table, 0))
		lh_doall_arg(&(*table)->piles,
			LHASH_DOALL_ARG_FN(int_unregister_cb), e);
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	}

static void int_cleanup_cb(ENGINE_PILE *p)
	{
	sk_ENGINE_free(p->sk);
	if(p->funct)
		engine_unlocked_finish(p->funct, 0);
	OPENSSL_free(p);
	}
static IMPLEMENT_LHASH_DOALL_FN(int_cleanup_cb,ENGINE_PILE *)
void engine_table_cleanup(ENGINE_TABLE **table)
	{
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	if(*table)
		{
		lh_doall(&(*table)->piles, LHASH_DOALL_FN(int_cleanup_cb));
		lh_free(&(*table)->piles);
		*table = NULL;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	}

/* Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references) for a given cipher 'nid' */
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select(ENGINE_TABLE **table, int nid)
#else
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l)
#endif
	{
	ENGINE *ret = NULL;
	ENGINE_PILE tmplate, *fnd=NULL;
	int initres, loop = 0;

	/* If 'engine_ciphers' is NULL, then it's absolutely *sure* that no
	 * ENGINEs have registered any implementations! */
	if(!(*table))
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, no "
			"registered for anything!\n", f, l, nid);
#endif
		return NULL;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	/* Check again inside the lock otherwise we could race against cleanup
	 * operations. But don't worry about a fprintf(stderr). */
	if(!int_table_check(table, 0))
		goto end;
	tmplate.nid = nid;
	fnd = lh_retrieve(&(*table)->piles, &tmplate);
	if(!fnd)
		goto end;
	if(fnd->funct && engine_unlocked_init(fnd->funct))
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
			"ENGINE '%s' cached\n", f, l, nid, fnd->funct->id);
#endif
		ret = fnd->funct;
		goto end;
		}
	if(fnd->uptodate)
		{
		ret = fnd->funct;
		goto end;
		}
trynext:
	ret = sk_ENGINE_value(fnd->sk, loop++);
	if(!ret)
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, no "
				"registered implementations would initialise\n",
				f, l, nid);
#endif
		goto end;
		}
#if 0
	/* Don't need to get a reference if we hold the lock. If the locking has
	 * to change in future, that would be different ... */
	ret->struct_ref++; engine_ref_debug(ret, 0, 1)
#endif
	/* Try and initialise the ENGINE if it's already functional *or* if the
	 * ENGINE_TABLE_FLAG_NOINIT flag is not set. */
	if((ret->funct_ref > 0) || !(table_flags & ENGINE_TABLE_FLAG_NOINIT))
		initres = engine_unlocked_init(ret);
	else
		initres = 0;
#if 0
	/* Release the structural reference */
	ret->struct_ref--; engine_ref_debug(ret, 0, -1);
#endif
	if(initres)
		{
		/* If we didn't have a default (functional reference) for this
		 * 'nid' (or we had one but for whatever reason we're now
		 * initialising a different one), use this opportunity to set
		 * 'funct'. */
		if((fnd->funct != ret) && engine_unlocked_init(ret))
			{
			/* If there was a previous default we release it. */
			if(fnd->funct)
				engine_unlocked_finish(fnd->funct, 0);
			/* We got an extra functional reference for the
			 * per-'nid' default */
			fnd->funct = ret;
#ifdef ENGINE_TABLE_DEBUG
			fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, "
				"setting default to '%s'\n", f, l, nid, ret->id);
#endif
			}
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
				"newly initialised '%s'\n", f, l, nid, ret->id);
#endif
		goto end;
		}
	goto trynext;
end:
	/* Whatever happened - we should "untouch" our uptodate file seeing as
	 * we have tried our best to find a functional reference for 'nid'. If
	 * it failed, it is unlikely to succeed again until some future
	 * registrations (or unregistrations) have taken place that affect that
	 * 'nid'. */
	if(fnd)
		fnd->uptodate = 1;
#ifdef ENGINE_TABLE_DEBUG
	if(ret)
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
				"ENGINE '%s'\n", f, l, nid, ret->id);
	else
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
				"'no matching ENGINE'\n", f, l, nid);
#endif
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	/* Whatever happened, any failed init()s are not failures in this
	 * context, so clear our error state. */
	ERR_clear_error();
	return ret;
	}
