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
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include "internal/cryptlib.h"
#include <openssl/lhash.h>


typedef struct {
    long argl;                  /* Arbitary long */
    void *argp;                 /* Arbitary void * */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
} CRYPTO_EX_DATA_FUNCS;

DECLARE_STACK_OF(CRYPTO_EX_DATA_FUNCS)

/*
 * State for each class; could just be a typedef, but this allows future
 * changes.
 */
typedef struct {
    STACK_OF(CRYPTO_EX_DATA_FUNCS) *meth;
} EX_CLASS_ITEM;

static EX_CLASS_ITEM ex_data[CRYPTO_EX_INDEX__COUNT];

/*
 * Return the EX_CLASS_ITEM from the "ex_data" array that corresponds to
 * a given class.  On success, *holds the lock.*
 */
static EX_CLASS_ITEM *def_get_class(int class_index)
{
    EX_CLASS_ITEM *ip;

    if (class_index < 0 || class_index >= CRYPTO_EX_INDEX__COUNT) {
        CRYPTOerr(CRYPTO_F_DEF_GET_CLASS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ip = &ex_data[class_index];
    CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
    if (ip->meth == NULL) {
        ip->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
        /* We push an initial value on the stack because the SSL
         * "app_data" routines use ex_data index zero.  See RT 3710. */
        if (ip->meth == NULL
            || !sk_CRYPTO_EX_DATA_FUNCS_push(ip->meth, NULL)) {
            CRYPTOerr(CRYPTO_F_DEF_GET_CLASS, ERR_R_MALLOC_FAILURE);
            CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
            return NULL;
        }
    }
    return ip;
}

static void cleanup_cb(CRYPTO_EX_DATA_FUNCS *funcs)
{
    OPENSSL_free(funcs);
}

/*
 * Release all "ex_data" state to prevent memory leaks. This can't be made
 * thread-safe without overhauling a lot of stuff, and shouldn't really be
 * called under potential race-conditions anyway (it's for program shutdown
 * after all).
 */
void CRYPTO_cleanup_all_ex_data(void)
{
    int i;

    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; ++i) {
        EX_CLASS_ITEM *ip = &ex_data[i];

        sk_CRYPTO_EX_DATA_FUNCS_pop_free(ip->meth, cleanup_cb);
        ip->meth = NULL;
    }
}

/*
 * Inside an existing class, get/register a new index.
 */
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func)
{
    int toret = -1;
    CRYPTO_EX_DATA_FUNCS *a;
    EX_CLASS_ITEM *ip = def_get_class(class_index);

    if (!ip)
        return -1;
    a = (CRYPTO_EX_DATA_FUNCS *)OPENSSL_malloc(sizeof(*a));
    if (!a) {
        CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    a->argl = argl;
    a->argp = argp;
    a->new_func = new_func;
    a->dup_func = dup_func;
    a->free_func = free_func;

    if (!sk_CRYPTO_EX_DATA_FUNCS_push(ip->meth, NULL)) {
        CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(a);
        goto err;
    }
    toret = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth) - 1;
    (void)sk_CRYPTO_EX_DATA_FUNCS_set(ip->meth, toret, a);

 err:
    CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
    return toret;
}

/*
 * Initialise a new CRYPTO_EX_DATA for use in a particular class - including
 * calling new() callbacks for each index in the class used by this variable
 * Thread-safe by copying a class's array of "CRYPTO_EX_DATA_FUNCS" entries
 * in the lock, then using them outside the lock. Note this only applies
 * to the global "ex_data" state (ie. class definitions), not 'ad' itself.
 */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    int mx, i;
    void *ptr;
    CRYPTO_EX_DATA_FUNCS **storage = NULL;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    EX_CLASS_ITEM *ip = def_get_class(class_index);

    if (!ip)
        return 0;

    ad->sk = NULL;

    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    if (mx > 0) {
        if (mx < (int)OSSL_NELEM(stack))
            storage = stack;
        else
            storage = OPENSSL_malloc(sizeof(*storage) * mx);
        if (storage)
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

    if (mx > 0 && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_NEW_EX_DATA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0; i < mx; i++) {
        if (storage[i] && storage[i]->new_func) {
            ptr = CRYPTO_get_ex_data(ad, i);
            storage[i]->new_func(obj, ptr, ad, i,
                                 storage[i]->argl, storage[i]->argp);
        }
    }
    if (storage != stack)
        OPENSSL_free(storage);
    return 1;
}

/*
 * Duplicate a CRYPTO_EX_DATA variable - including calling dup() callbacks
 * for each index in the class used by this variable
 */
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       CRYPTO_EX_DATA *from)
{
    int mx, j, i;
    char *ptr;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    CRYPTO_EX_DATA_FUNCS **storage = NULL;
    EX_CLASS_ITEM *ip;

    if (from->sk == NULL)
        /* Nothing to copy over */
        return 1;
    if ((ip = def_get_class(class_index)) == NULL)
        return 0;

    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    j = sk_void_num(from->sk);
    if (j < mx)
        mx = j;
    if (mx > 0) {
        if (mx < (int)OSSL_NELEM(stack))
            storage = stack;
        else
            storage = OPENSSL_malloc(sizeof(*storage) * mx);
        if (storage)
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

    if (mx > 0 && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_DUP_EX_DATA, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (i = 0; i < mx; i++) {
        ptr = CRYPTO_get_ex_data(from, i);
        if (storage[i] && storage[i]->dup_func)
            storage[i]->dup_func(to, from, &ptr, i,
                                 storage[i]->argl, storage[i]->argp);
        CRYPTO_set_ex_data(to, i, ptr);
    }
    if (storage != stack)
        OPENSSL_free(storage);
    return 1;
}


/*
 * Cleanup a CRYPTO_EX_DATA variable - including calling free() callbacks for
 * each index in the class used by this variable
 */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    int mx, i;
    EX_CLASS_ITEM *ip;
    void *ptr;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    CRYPTO_EX_DATA_FUNCS **storage = NULL;

    if ((ip = def_get_class(class_index)) == NULL)
        return;

    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    if (mx > 0) {
        if (mx < (int)OSSL_NELEM(stack))
            storage = stack;
        else
            storage = OPENSSL_malloc(sizeof(*storage) * mx);
        if (storage)
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

    if (mx > 0 && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_FREE_EX_DATA, ERR_R_MALLOC_FAILURE);
        return;
    }
    for (i = 0; i < mx; i++) {
        if (storage[i] && storage[i]->free_func) {
            ptr = CRYPTO_get_ex_data(ad, i);
            storage[i]->free_func(obj, ptr, ad, i,
                                  storage[i]->argl, storage[i]->argp);
        }
    }

    if (storage != stack)
        OPENSSL_free(storage);
    sk_void_free(ad->sk);
    ad->sk = NULL;
}

/*
 * For a given CRYPTO_EX_DATA variable, set the value corresponding to a
 * particular index in the class used by this variable
 */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)
{
    int i;

    if (ad->sk == NULL) {
        if ((ad->sk = sk_void_new_null()) == NULL) {
            CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    for (i = sk_void_num(ad->sk); i <= idx; ++i) {
        if (!sk_void_push(ad->sk, NULL)) {
            CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    sk_void_set(ad->sk, idx, val);
    return 1;
}

/*
 * For a given CRYPTO_EX_DATA_ variable, get the value corresponding to a
 * particular index in the class used by this variable
 */
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx)
{
    if (ad->sk == NULL || idx >= sk_void_num(ad->sk))
        return NULL;
    return sk_void_value(ad->sk, idx);
}
