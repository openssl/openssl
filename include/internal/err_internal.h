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
#include "err_local.h"

static ossl_inline ERR_STATE *ERR_get_state(void)
{
    return ossl_err_get_state_int(0);
}

static ossl_inline int ERR_STATE_set_mark(ERR_STATE *es)
{
    if (es == NULL)
        return 0;

    if (es->bottom == es->top)
        return 0;
    es->err_marks[es->top]++;
    return 1;
}

static ossl_inline int ERR_STATE_pop_to_mark(ERR_STATE *es)
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

static ossl_inline int ERR_STATE_count_to_mark(ERR_STATE *es)
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

static ossl_inline int ERR_STATE_clear_last_mark(ERR_STATE *es)
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

#endif
