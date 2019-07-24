/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include "err_locl.h"

void ERR_new(void)
{
    ERR_STATE *es;

    es = ERR_get_state();
    if (es == NULL)
        return;

    /* Allocate a slot */
    err_allocate(es);
    err_clear(es, es->top);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    ERR_STATE *es;

    es = ERR_get_state();
    if (es == NULL)
        return;

    err_set_debug(es, es->top, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    ERR_vset_error(lib, reason, fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    ERR_STATE *es;
    char *buf = NULL;
    size_t buf_len = 0;
    unsigned long flags = 0;

    es = ERR_get_state();
    if (es == NULL)
        return;

    if (fmt != NULL
        && (buf = OPENSSL_malloc(ERR_MAX_DATA_SIZE)) != NULL) {
        int printed_len = 0;
        char *rbuf = NULL;

        printed_len = BIO_vsnprintf(buf, ERR_MAX_DATA_SIZE, fmt, args);
        if (printed_len > 0)
            buf_len += printed_len;
        buf[buf_len] = '\0';

        /* Try to reduce the size */
        rbuf = OPENSSL_realloc(buf, buf_len + 1);

        /*
         * According to documentation, realloc leaves the old buffer untouched
         * if it fails.  We could deal with this in two ways, either free the
         * buffer, or simply keep it.  We choose the former, because that's
         * what ERR_add_error_vdata() does on the same kind of failure.
         */
        if (rbuf == NULL)
            OPENSSL_free(buf);
        buf = rbuf;

        if (buf != NULL)
            flags = ERR_TXT_MALLOCED | ERR_TXT_STRING;
    }

    err_clear_data(es, es->top);
    err_set_error(es, es->top, lib, reason);
    err_set_data(es, es->top, buf, flags);
}
