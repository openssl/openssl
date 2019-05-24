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

static void ossl_init_thread_stop(THREAD_EVENT_HANDLER **hands);

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

void OPENSSL_thread_stop(void)
{
    if (destructor_key.sane != -1)
        ossl_init_thread_stop(ossl_init_get_thread_local(0));
}

int ossl_init_thread_start(OPENSSL_CTX *ctx, ossl_thread_stop_handler_fn handfn)
{
    THREAD_EVENT_HANDLER **hands;
    THREAD_EVENT_HANDLER *hand;

    if (!OPENSSL_init_crypto(0, NULL))
        return 0;

    hands = ossl_init_get_thread_local(1);

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
