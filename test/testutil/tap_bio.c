/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "tu_local.h"

typedef struct bio_tap_ctx_struct {
    size_t newline;
    size_t leadingspaces;
} BIO_TAP_CTX;

static int tap_write_ex(BIO *b, const char *buf, size_t size, size_t *in_size);
static int tap_read_ex(BIO *b, char *buf, size_t size, size_t *out_size);
static int tap_puts(BIO *b, const char *str);
static int tap_gets(BIO *b, char *str, int size);
static long tap_ctrl(BIO *b, int cmd, long arg1, void *arg2);
static int tap_new(BIO *b);
static int tap_free(BIO *b);
static long tap_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

const BIO_METHOD *BIO_f_tap(void)
{
    static BIO_METHOD *tap = NULL;

    if (tap == NULL) {
        tap = BIO_meth_new(BIO_TYPE_START | BIO_TYPE_FILTER, "tap");
        if (tap != NULL) {
            BIO_meth_set_write_ex(tap, tap_write_ex);
            BIO_meth_set_read_ex(tap, tap_read_ex);
            BIO_meth_set_puts(tap, tap_puts);
            BIO_meth_set_gets(tap, tap_gets);
            BIO_meth_set_ctrl(tap, tap_ctrl);
            BIO_meth_set_create(tap, tap_new);
            BIO_meth_set_destroy(tap, tap_free);
            BIO_meth_set_callback_ctrl(tap, tap_callback_ctrl);
        }
    }
    return tap;
}

static int tap_new(BIO *b)
{
    BIO_TAP_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return 0;
    ctx->newline = 1;
    ctx->leadingspaces = 0;
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int tap_free(BIO *b)
{
    if (b == NULL)
        return 0;
    OPENSSL_free(BIO_get_data(b));
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

static int tap_read_ex(BIO *b, char *buf, size_t size, size_t *out_size)
{
    BIO *next = BIO_next(b);
    int ret = 0;

    ret = BIO_read_ex(next, buf, size, out_size);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ret;
}

/*
 * Output a string to the specified bio and return 1 if successful.
 */
static int write_string(BIO *b, const char *buf, size_t n)
{
    size_t m;

    return BIO_write_ex(b, buf, n, &m) != 0 && m == n;
}

/*
 * Output the specified number of spaces to the bio and return 1 if successful.
 */
static int spaces(BIO *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (!write_string(b, " ", 1))
            return 0;
    return 1;
}

/*
 * Write some data.
 *
 * This function implements a simple state machine that detects new lines.
 * It indents the output and prefixes it with a '#' character if one isn't
 * already present.  Indentation after a '#' and at the beginning of a line
 * without a leading '#' is preserved.
 *
 * It returns the number of input characters that were output in in_size.
 * More characters than this will likely have been output however any calling
 * code will be unable to correctly assess the actual number of characters
 * emitted and would be prone to failure if the actual number were returned.
 */
static int tap_write_ex(BIO *b, const char *buf, size_t size, size_t *in_size)
{
    BIO *next = BIO_next(b);
    BIO_TAP_CTX *ctx = (BIO_TAP_CTX *)BIO_get_data(b);
    const size_t indent = subtest_level();
    const char *p = buf;
    size_t i, m, n;

    for (i = 0; i < size; i++) {
        if (ctx->newline) {
            switch (buf[i]) {
            case ' ':
                ctx->leadingspaces++;
                break;

            case '\t':
                ctx->leadingspaces = (8 + ctx->leadingspaces) & ~7;
                break;

            case '\n':
                ctx->leadingspaces = 0;
                if (!write_string(next, "\n", 1))
                    goto err;
                break;

            case '#':
                if (!spaces(next, indent))
                    goto err;
                p = buf + i;
                ctx->leadingspaces = ctx->newline = 0;
                break;

            default:
                if (!spaces(next, indent) || !write_string(next, "# ", 2))
                    goto err;
                p = buf + i;
                if (!spaces(next, ctx->leadingspaces))
                    goto err;
                ctx->leadingspaces = ctx->newline = 0;
                break;
            }
        } else if (buf[i] == '\n') {
            n = buf + i - p + 1;
            if (BIO_write_ex(next, p, n, &m) == 0 || m != n) {
                *in_size = p + m - buf;
                return 0;
            }
            p = buf + i + 1;
            ctx->leadingspaces = 0;
            ctx->newline = 1;
        }
    }

    /* Output any residual characters from the end. */
    if (!ctx->newline && p != buf + size - 1) {
        n = buf + i - p;
        if (BIO_write_ex(next, p, n, &m) == 0 || m != n) {
            *in_size = p + m - buf;
            return 0;
        }
    }
    *in_size = size;
    return 1;

err:
    *in_size = p - buf;
    return 0;
}

static long tap_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(b);
    BIO_TAP_CTX *ctx = (BIO_TAP_CTX *)BIO_get_data(b);
 
    switch (cmd) {
    case BIO_CTRL_RESET:
        ctx->leadingspaces = 0;
        ctx->newline = 1;
        break;

    default:
        break;
    }
    return BIO_ctrl(next, cmd, num, ptr);
}

static long tap_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
    return BIO_callback_ctrl(BIO_next(b), cmd, fp);
}

static int tap_gets(BIO *b, char *buf, int size)
{
    return BIO_gets(BIO_next(b), buf, size);
}

static int tap_puts(BIO *b, const char *str)
{
    size_t m;

    if (!tap_write_ex(b, str, strlen(str), &m))
        return 0;
    return m;
}
