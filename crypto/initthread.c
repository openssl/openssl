/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/cryptlib_int.h"

typedef struct thread_event_handler_st THREAD_EVENT_HANDLER;
struct thread_event_handler_st {
    OPENSSL_CTX *ctx;
    ossl_thread_stop_handler_fn handfn;
    THREAD_EVENT_HANDLER *next;
};

static void ossl_init_thread_stop(THREAD_EVENT_HANDLER **hands);

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
    ossl_init_thread_stop((THREAD_EVENT_HANDLER **)hands);
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

static THREAD_EVENT_HANDLER **ossl_init_get_thread_local(int alloc)
{
    THREAD_EVENT_HANDLER **hands =
        CRYPTO_THREAD_get_local(&destructor_key.value);

    if (alloc) {
        if (hands == NULL
            && (hands = OPENSSL_zalloc(sizeof(*hands))) != NULL
            && !CRYPTO_THREAD_set_local(&destructor_key.value, hands)) {
            OPENSSL_free(hands);
            return NULL;
        }
    } else {
        CRYPTO_THREAD_set_local(&destructor_key.value, NULL);
    }

    return hands;
}

void OPENSSL_thread_stop(void)
{
    if (destructor_key.sane != -1)
        ossl_init_thread_stop(ossl_init_get_thread_local(0));
}
#else
static void *thread_event_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    THREAD_EVENT_HANDLER **hands = NULL;
    CRYPTO_THREAD_LOCAL *tlocal = OPENSSL_zalloc(sizeof(CRYPTO_THREAD_LOCAL));

    if (tlocal == NULL)
        return NULL;

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

static void thread_event_ossl_ctx_free(void *vtlocal)
{
    CRYPTO_THREAD_LOCAL *tlocal = vtlocal;
    THREAD_EVENT_HANDLER **hands = CRYPTO_THREAD_get_local(tlocal);

    if (hands != NULL)
        ossl_init_thread_stop(hands);

    OPENSSL_free(tlocal);
}

static const OPENSSL_CTX_METHOD thread_event_ossl_ctx_method = {
    thread_event_ossl_ctx_new,
    thread_event_ossl_ctx_free,
};

void fips_thread_stop(OPENSSL_CTX *ctx)
{
    THREAD_EVENT_HANDLER **hands;

    hands = openssl_ctx_get_data(ctx, OPENSSL_CTX_THREAD_EVENT_HANDLER_INDEX,
                                 &thread_event_ossl_ctx_method);
    if (hands != NULL)
        ossl_init_thread_stop(hands);
}
#endif /* FIPS_MODE */

static void ossl_init_thread_stop(THREAD_EVENT_HANDLER **hands)
{
    THREAD_EVENT_HANDLER *curr, *prev = NULL;

    /* Can't do much about this */
    if (hands == NULL)
        return;

    curr = *hands;
    while (curr != NULL) {
        curr->handfn(curr->ctx);
        prev = curr;
        curr = curr->next;
        OPENSSL_free(prev);
    }

    OPENSSL_free(hands);
}

int ossl_init_thread_start(OPENSSL_CTX *ctx, ossl_thread_stop_handler_fn handfn)
{
    THREAD_EVENT_HANDLER **hands;
    THREAD_EVENT_HANDLER *hand;

#ifdef FIPS_MODE
    /*
     * In FIPS mode the list of THREAD_EVENT_HANDLERs is unique per combination
     * of OPENSSL_CTX and thread. This is because in FIPS mode each OPENSSL_CTX
     * gets informed about thread stop events individually.
     */
    hands = openssl_ctx_get_data(ctx, OPENSSL_CTX_THREAD_EVENT_HANDLER_INDEX,
                                 &thread_event_ossl_ctx_method);
#else
    /*
     * Outside of FIPS mode the list of THREAD_EVENT_HANDLERs is unique per
     * thread, but may hold multiple OPENSSL_CTXs. We only get told about
     * thread stop events globally, so we have to ensure all affected
     * OPENSSL_CTXs are informed.
     */
    hands = ossl_init_get_thread_local(1);
#endif

    if (hands == NULL)
        return 0;

    hand = OPENSSL_malloc(sizeof(*hand));
    if (hand == NULL)
        return 0;

    hand->handfn = handfn;
    hand->ctx = ctx;
    hand->next = *hands;
    *hands = hand;

    return 1;
}
