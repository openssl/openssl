/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include "internal/cryptlib_int.h"
#include "internal/providercommon.h"

#ifdef FIPS_MODE
/*
 * Thread aware code may want to be told about thread stop events. We register
 * to hear about those thread stop events when we see a new thread has started.
 * We call the ossl_init_thread_start function to do that. In the FIPS provider
 * we have our own copy of ossl_init_thread_start, which cascades notifications
 * about threads stopping from libcrypto to all the code in the FIPS provider
 * that needs to know about it.
 * 
 * The FIPS provider tells libcrypto about which threads it is interested in
 * by calling "c_thread_start" which is a function pointer created during
 * provider initialisation (i.e. OSSL_init_provider).
 */
extern OSSL_core_thread_start_fn *c_thread_start;
#endif

typedef struct thread_event_handler_st THREAD_EVENT_HANDLER;
struct thread_event_handler_st {
    void *arg;
    OSSL_thread_stop_handler_fn handfn;
    THREAD_EVENT_HANDLER *next;
};

static void ossl_init_thread_stop(void *arg, THREAD_EVENT_HANDLER **hands);

static THREAD_EVENT_HANDLER **
ossl_init_get_thread_local(CRYPTO_THREAD_LOCAL *local, int alloc, int keep)
{
    THREAD_EVENT_HANDLER **hands = CRYPTO_THREAD_get_local(local);

    if (alloc) {
        if (hands == NULL
            && (hands = OPENSSL_zalloc(sizeof(*hands))) != NULL
            && !CRYPTO_THREAD_set_local(local, hands)) {
            OPENSSL_free(hands);
            return NULL;
        }
    } else if (!keep) {
        CRYPTO_THREAD_set_local(local, NULL);
    }

    return hands;
}

#ifndef FIPS_MODE
/*
 * Since per-thread-specific-data destructors are not universally
 * available, i.e. not on Windows, only below CRYPTO_THREAD_LOCAL key
 * is assumed to have destructor associated. And then an effort is made
 * to call this single destructor on non-pthread platform[s].
 *
 * Initial value is "impossible". It is used as guard value to shortcut
 * destructor for threads terminating before libcrypto is initialized or
 * after it's de-initialized. Access to the key doesn't have to be
 * serialized for the said threads, because they didn't use libcrypto
 * and it doesn't matter if they pick "impossible" or derefernce real
 * key value and pull NULL past initialization in the first thread that
 * intends to use libcrypto.
 */
static union {
    long sane;
    CRYPTO_THREAD_LOCAL value;
} destructor_key = { -1 };

static void ossl_init_thread_destructor(void *hands)
{
    ossl_init_thread_stop(NULL, (THREAD_EVENT_HANDLER **)hands);
    OPENSSL_free(hands);
}

int init_thread(void)
{
    if (!CRYPTO_THREAD_init_local(&destructor_key.value,
                                  ossl_init_thread_destructor))
        return 0;

    return 1;
}

void cleanup_thread(void)
{
    CRYPTO_THREAD_cleanup_local(&destructor_key.value);
    destructor_key.sane = -1;
}

void OPENSSL_thread_stop(void)
{
    if (destructor_key.sane != -1) {
        THREAD_EVENT_HANDLER **hands
            = ossl_init_get_thread_local(&destructor_key.value, 0, 0);
        ossl_init_thread_stop(NULL, hands);
        OPENSSL_free(hands);
    }
}

void ossl_ctx_thread_stop(void *arg)
{
    if (destructor_key.sane != -1) {
        THREAD_EVENT_HANDLER **hands
            = ossl_init_get_thread_local(&destructor_key.value, 0, 1);
        ossl_init_thread_stop(arg, hands);
    }
}

#else

static void *thread_event_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    THREAD_EVENT_HANDLER **hands = NULL;
    CRYPTO_THREAD_LOCAL *tlocal = OPENSSL_zalloc(sizeof(*tlocal));

    if (tlocal == NULL)
        return NULL;

    if (!CRYPTO_THREAD_init_local(tlocal,  NULL)) {
        goto err;
    }

    hands = OPENSSL_zalloc(sizeof(*hands));
    if (hands == NULL)
        goto err;

    if (!CRYPTO_THREAD_set_local(tlocal, hands))
        goto err;

    return tlocal;
 err:
    OPENSSL_free(hands);
    OPENSSL_free(tlocal);
    return NULL;
}

static void thread_event_ossl_ctx_free(void *tlocal)
{
    OPENSSL_free(tlocal);
}

static const OPENSSL_CTX_METHOD thread_event_ossl_ctx_method = {
    thread_event_ossl_ctx_new,
    thread_event_ossl_ctx_free,
};

void ossl_ctx_thread_stop(void *arg)
{
    THREAD_EVENT_HANDLER **hands;
    OPENSSL_CTX *ctx = arg;
    CRYPTO_THREAD_LOCAL *local
        = openssl_ctx_get_data(ctx, OPENSSL_CTX_THREAD_EVENT_HANDLER_INDEX,
                               &thread_event_ossl_ctx_method);

    if (local == NULL)
        return;
    hands = ossl_init_get_thread_local(local, 0, 0);
    ossl_init_thread_stop(arg, hands);
    OPENSSL_free(hands);
}
#endif /* FIPS_MODE */


static void ossl_init_thread_stop(void *arg, THREAD_EVENT_HANDLER **hands)
{
    THREAD_EVENT_HANDLER *curr, *prev = NULL;

    /* Can't do much about this */
    if (hands == NULL)
        return;

    curr = *hands;
    while (curr != NULL) {
        if (arg != NULL && curr->arg != arg) {
            curr = curr->next;
            continue;
        }
        curr->handfn(curr->arg);
        prev = curr;
        curr = curr->next;
        if (prev == *hands)
            *hands = curr;
        OPENSSL_free(prev);
    }
}

int ossl_init_thread_start(void *arg, OSSL_thread_stop_handler_fn handfn)
{
    THREAD_EVENT_HANDLER **hands;
    THREAD_EVENT_HANDLER *hand;
#ifdef FIPS_MODE
    OPENSSL_CTX *ctx = arg;

    /*
     * In FIPS mode the list of THREAD_EVENT_HANDLERs is unique per combination
     * of OPENSSL_CTX and thread. This is because in FIPS mode each OPENSSL_CTX
     * gets informed about thread stop events individually.
     */
    CRYPTO_THREAD_LOCAL *local
        = openssl_ctx_get_data(ctx, OPENSSL_CTX_THREAD_EVENT_HANDLER_INDEX,
                               &thread_event_ossl_ctx_method);
#else
    /*
     * Outside of FIPS mode the list of THREAD_EVENT_HANDLERs is unique per
     * thread, but may hold multiple OPENSSL_CTXs. We only get told about
     * thread stop events globally, so we have to ensure all affected
     * OPENSSL_CTXs are informed.
     */
    CRYPTO_THREAD_LOCAL *local = &destructor_key.value;
#endif

    hands = ossl_init_get_thread_local(local, 1, 0);
    if (hands == NULL)
        return 0;

#ifdef FIPS_MODE
    if (*hands == NULL) {
        /*
         * We've not yet registered any handlers for this thread. We need to get
         * libcrypto to tell us about later thread stop events. c_thread_start
         * is a callback to libcrypto defined in fipsprov.c
         */
        if (!c_thread_start(FIPS_get_provider(ctx), ossl_ctx_thread_stop))
            return 0;
    }
#endif

    hand = OPENSSL_malloc(sizeof(*hand));
    if (hand == NULL)
        return 0;

    hand->handfn = handfn;
    hand->arg = arg;
    hand->next = *hands;
    *hands = hand;

    return 1;
}
