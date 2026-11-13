/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ERR_INTERNAL_H
#define OPENSSL_ERR_INTERNAL_H

#include <openssl/err.h>
#include "../crypto/err/err_local.h"

#ifdef OPENSSL_SMALL_FOOTPRINT
#define ossl_err_get_state() NULL
/*
 * ossl_err_state_set_mark has to be used before any of the
 * other functions below, so we use this as an opportunity
 * to mark the ERR_STATE variable that would otherwise be
 * unused in SMALL_FOOTPRINT mode as used to the compiler
 */
#define ossl_err_state_set_mark(es) \
    do {                            \
        (void)es;                   \
        ERR_set_mark();             \
    } while (0)

#define ossl_err_state_pop_to_mark(es) ERR_pop_to_mark()
#define ossl_err_state_count_to_mark(es) ERR_count_to_mark()
#define ossl_err_state_clear_last_mark(es) ERR_clear_last_mark()
#else
#include "internal/threads_common.h"

/**
 * @see ERR_set_mark(3)
 */
static ossl_inline int ossl_err_state_set_mark(ERR_STATE *es)
{
    if (es == NULL)
        return 0;

    if (es->bottom == es->top)
        return 0;
    es->err_marks[es->top]++;
    return 1;
}

/**
 * @see ERR_pop_to_mark(3)
 */
static ossl_inline int ossl_err_state_pop_to_mark(ERR_STATE *es)
{
    if (es == NULL)
        return 0;

    while (es->bottom != es->top
        && es->err_marks[es->top] == 0) {
        err_clear(es, es->top, 0);
        es->top = es->top > 0 ? es->top - 1 : ERR_NUM_ERRORS - 1;
    }

    if (es->bottom == es->top)
        return 0;
    es->err_marks[es->top]--;
    return 1;
}

/**
 * @see ERR_count_to_mark(3)
 */
static ossl_inline int ossl_err_state_count_to_mark(ERR_STATE *es)
{
    int count = 0, top;

    if (es == NULL)
        return 0;

    top = es->top;
    while (es->bottom != top
        && es->err_marks[top] == 0) {
        ++count;
        top = top > 0 ? top - 1 : ERR_NUM_ERRORS - 1;
    }

    return count;
}

/**
 * @see ERR_clear_last_mark(3)
 */
static ossl_inline int ossl_err_state_clear_last_mark(ERR_STATE *es)
{
    int top;

    if (es == NULL)
        return 0;

    top = es->top;
    while (es->bottom != top
        && es->err_marks[top] == 0) {
        top = top > 0 ? top - 1 : ERR_NUM_ERRORS - 1;
    }

    if (es->bottom == top)
        return 0;
    es->err_marks[top]--;
    return 1;
}

/**
 * @brief get the current threads error state
 */
static ossl_inline ERR_STATE *ossl_err_get_state(void)
{
    ERR_STATE *state = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
        CRYPTO_THREAD_NO_CONTEXT);
    if (state == NULL) {
        /*
         * Use the exported api to force creation of thread err state
         */
        ERR_set_mark();
        ERR_clear_last_mark();
        state = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY,
            CRYPTO_THREAD_NO_CONTEXT);
    }

    return state;
}

#endif /* OPENSSL_SMALL_FOOTPRINT */

#endif
