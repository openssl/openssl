/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <opentls/crypto.h>
#include "internal/bio.h"
#include <opentls/err.h>
#include "tls_local.h"

static int tls_write(BIO *h, const char *buf, size_t size, size_t *written);
static int tls_read(BIO *b, char *buf, size_t size, size_t *readbytes);
static int tls_puts(BIO *h, const char *str);
static long tls_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int tls_new(BIO *h);
static int tls_free(BIO *data);
static long tls_callback_ctrl(BIO *h, int cmd, BIO_info_cb *fp);
typedef struct bio_tls_st {
    tls *tls;                   /* The tls handle :-) */
    /* re-negotiate every time the total number of bytes is this size */
    int num_renegotiates;
    unsigned long renegotiate_count;
    size_t byte_count;
    unsigned long renegotiate_timeout;
    unsigned long last_time;
} BIO_tls;

static const BIO_METHOD methods_tlsp = {
    BIO_TYPE_tls,
    "tls",
    tls_write,
    NULL,                       /* tls_write_old, */
    tls_read,
    NULL,                       /* tls_read_old,  */
    tls_puts,
    NULL,                       /* tls_gets,      */
    tls_ctrl,
    tls_new,
    tls_free,
    tls_callback_ctrl,
};

const BIO_METHOD *BIO_f_tls(void)
{
    return &methods_tlsp;
}

static int tls_new(BIO *bi)
{
    BIO_tls *bs = OPENtls_zalloc(sizeof(*bs));

    if (bs == NULL) {
        BIOerr(BIO_F_tls_NEW, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    BIO_set_init(bi, 0);
    BIO_set_data(bi, bs);
    /* Clear all flags */
    BIO_clear_flags(bi, ~0);

    return 1;
}

static int tls_free(BIO *a)
{
    BIO_tls *bs;

    if (a == NULL)
        return 0;
    bs = BIO_get_data(a);
    if (bs->tls != NULL)
        tls_shutdown(bs->tls);
    if (BIO_get_shutdown(a)) {
        if (BIO_get_init(a))
            tls_free(bs->tls);
        /* Clear all flags */
        BIO_clear_flags(a, ~0);
        BIO_set_init(a, 0);
    }
    OPENtls_free(bs);
    return 1;
}

static int tls_read(BIO *b, char *buf, size_t size, size_t *readbytes)
{
    int ret = 1;
    BIO_tls *sb;
    tls *tls;
    int retry_reason = 0;
    int r = 0;

    if (buf == NULL)
        return 0;
    sb = BIO_get_data(b);
    tls = sb->tls;

    BIO_clear_retry_flags(b);

    ret = tls_read_internal(tls, buf, size, readbytes);

    switch (tls_get_error(tls, ret)) {
    case tls_ERROR_NONE:
        if (sb->renegotiate_count > 0) {
            sb->byte_count += *readbytes;
            if (sb->byte_count > sb->renegotiate_count) {
                sb->byte_count = 0;
                sb->num_renegotiates++;
                tls_renegotiate(tls);
                r = 1;
            }
        }
        if ((sb->renegotiate_timeout > 0) && (!r)) {
            unsigned long tm;

            tm = (unsigned long)time(NULL);
            if (tm > sb->last_time + sb->renegotiate_timeout) {
                sb->last_time = tm;
                sb->num_renegotiates++;
                tls_renegotiate(tls);
            }
        }

        break;
    case tls_ERROR_WANT_READ:
        BIO_set_retry_read(b);
        break;
    case tls_ERROR_WANT_WRITE:
        BIO_set_retry_write(b);
        break;
    case tls_ERROR_WANT_X509_LOOKUP:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_tls_X509_LOOKUP;
        break;
    case tls_ERROR_WANT_ACCEPT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_ACCEPT;
        break;
    case tls_ERROR_WANT_CONNECT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_CONNECT;
        break;
    case tls_ERROR_SYSCALL:
    case tls_ERROR_tls:
    case tls_ERROR_ZERO_RETURN:
    default:
        break;
    }

    BIO_set_retry_reason(b, retry_reason);

    return ret;
}

static int tls_write(BIO *b, const char *buf, size_t size, size_t *written)
{
    int ret, r = 0;
    int retry_reason = 0;
    tls *tls;
    BIO_tls *bs;

    if (buf == NULL)
        return 0;
    bs = BIO_get_data(b);
    tls = bs->tls;

    BIO_clear_retry_flags(b);

    ret = tls_write_internal(tls, buf, size, written);

    switch (tls_get_error(tls, ret)) {
    case tls_ERROR_NONE:
        if (bs->renegotiate_count > 0) {
            bs->byte_count += *written;
            if (bs->byte_count > bs->renegotiate_count) {
                bs->byte_count = 0;
                bs->num_renegotiates++;
                tls_renegotiate(tls);
                r = 1;
            }
        }
        if ((bs->renegotiate_timeout > 0) && (!r)) {
            unsigned long tm;

            tm = (unsigned long)time(NULL);
            if (tm > bs->last_time + bs->renegotiate_timeout) {
                bs->last_time = tm;
                bs->num_renegotiates++;
                tls_renegotiate(tls);
            }
        }
        break;
    case tls_ERROR_WANT_WRITE:
        BIO_set_retry_write(b);
        break;
    case tls_ERROR_WANT_READ:
        BIO_set_retry_read(b);
        break;
    case tls_ERROR_WANT_X509_LOOKUP:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_tls_X509_LOOKUP;
        break;
    case tls_ERROR_WANT_CONNECT:
        BIO_set_retry_special(b);
        retry_reason = BIO_RR_CONNECT;
    case tls_ERROR_SYSCALL:
    case tls_ERROR_tls:
    default:
        break;
    }

    BIO_set_retry_reason(b, retry_reason);

    return ret;
}

static long tls_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    tls **tlsp, *tls;
    BIO_tls *bs, *dbs;
    BIO *dbio, *bio;
    long ret = 1;
    BIO *next;

    bs = BIO_get_data(b);
    next = BIO_next(b);
    tls = bs->tls;
    if ((tls == NULL) && (cmd != BIO_C_SET_tls))
        return 0;
    switch (cmd) {
    case BIO_CTRL_RESET:
        tls_shutdown(tls);

        if (tls->handshake_func == tls->method->tls_connect)
            tls_set_connect_state(tls);
        else if (tls->handshake_func == tls->method->tls_accept)
            tls_set_accept_state(tls);

        if (!tls_clear(tls)) {
            ret = 0;
            break;
        }

        if (next != NULL)
            ret = BIO_ctrl(next, cmd, num, ptr);
        else if (tls->rbio != NULL)
            ret = BIO_ctrl(tls->rbio, cmd, num, ptr);
        else
            ret = 1;
        break;
    case BIO_CTRL_INFO:
        ret = 0;
        break;
    case BIO_C_tls_MODE:
        if (num)                /* client mode */
            tls_set_connect_state(tls);
        else
            tls_set_accept_state(tls);
        break;
    case BIO_C_SET_tls_RENEGOTIATE_TIMEOUT:
        ret = bs->renegotiate_timeout;
        if (num < 60)
            num = 5;
        bs->renegotiate_timeout = (unsigned long)num;
        bs->last_time = (unsigned long)time(NULL);
        break;
    case BIO_C_SET_tls_RENEGOTIATE_BYTES:
        ret = bs->renegotiate_count;
        if ((long)num >= 512)
            bs->renegotiate_count = (unsigned long)num;
        break;
    case BIO_C_GET_tls_NUM_RENEGOTIATES:
        ret = bs->num_renegotiates;
        break;
    case BIO_C_SET_tls:
        if (tls != NULL) {
            tls_free(b);
            if (!tls_new(b))
                return 0;
        }
        BIO_set_shutdown(b, num);
        tls = (tls *)ptr;
        bs->tls = tls;
        bio = tls_get_rbio(tls);
        if (bio != NULL) {
            if (next != NULL)
                BIO_push(bio, next);
            BIO_set_next(b, bio);
            BIO_up_ref(bio);
        }
        BIO_set_init(b, 1);
        break;
    case BIO_C_GET_tls:
        if (ptr != NULL) {
            tlsp = (tls **)ptr;
            *tlsp = tls;
        } else
            ret = 0;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = BIO_get_shutdown(b);
        break;
    case BIO_CTRL_SET_CLOSE:
        BIO_set_shutdown(b, (int)num);
        break;
    case BIO_CTRL_WPENDING:
        ret = BIO_ctrl(tls->wbio, cmd, num, ptr);
        break;
    case BIO_CTRL_PENDING:
        ret = tls_pending(tls);
        if (ret == 0)
            ret = BIO_pending(tls->rbio);
        break;
    case BIO_CTRL_FLUSH:
        BIO_clear_retry_flags(b);
        ret = BIO_ctrl(tls->wbio, cmd, num, ptr);
        BIO_copy_next_retry(b);
        break;
    case BIO_CTRL_PUSH:
        if ((next != NULL) && (next != tls->rbio)) {
            /*
             * We are going to pass ownership of next to the tls object...but
             * we don't own a reference to pass yet - so up ref
             */
            BIO_up_ref(next);
            tls_set_bio(tls, next, next);
        }
        break;
    case BIO_CTRL_POP:
        /* Only detach if we are the BIO explicitly being popped */
        if (b == ptr) {
            /* This will clear the reference we obtained during push */
            tls_set_bio(tls, NULL, NULL);
        }
        break;
    case BIO_C_DO_STATE_MACHINE:
        BIO_clear_retry_flags(b);

        BIO_set_retry_reason(b, 0);
        ret = (int)tls_do_handshake(tls);

        switch (tls_get_error(tls, (int)ret)) {
        case tls_ERROR_WANT_READ:
            BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
            break;
        case tls_ERROR_WANT_WRITE:
            BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY);
            break;
        case tls_ERROR_WANT_CONNECT:
            BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
            BIO_set_retry_reason(b, BIO_get_retry_reason(next));
            break;
        case tls_ERROR_WANT_X509_LOOKUP:
            BIO_set_retry_special(b);
            BIO_set_retry_reason(b, BIO_RR_tls_X509_LOOKUP);
            break;
        default:
            break;
        }
        break;
    case BIO_CTRL_DUP:
        dbio = (BIO *)ptr;
        dbs = BIO_get_data(dbio);
        tls_free(dbs->tls);
        dbs->tls = tls_dup(tls);
        dbs->num_renegotiates = bs->num_renegotiates;
        dbs->renegotiate_count = bs->renegotiate_count;
        dbs->byte_count = bs->byte_count;
        dbs->renegotiate_timeout = bs->renegotiate_timeout;
        dbs->last_time = bs->last_time;
        ret = (dbs->tls != NULL);
        break;
    case BIO_C_GET_FD:
        ret = BIO_ctrl(tls->rbio, cmd, num, ptr);
        break;
    case BIO_CTRL_SET_CALLBACK:
        ret = 0; /* use callback ctrl */
        break;
    default:
        ret = BIO_ctrl(tls->rbio, cmd, num, ptr);
        break;
    }
    return ret;
}

static long tls_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)
{
    tls *tls;
    BIO_tls *bs;
    long ret = 1;

    bs = BIO_get_data(b);
    tls = bs->tls;
    switch (cmd) {
    case BIO_CTRL_SET_CALLBACK:
        ret = BIO_callback_ctrl(tls->rbio, cmd, fp);
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int tls_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = BIO_write(bp, str, n);
    return ret;
}

BIO *BIO_new_buffer_tls_connect(tls_CTX *ctx)
{
#ifndef OPENtls_NO_SOCK
    BIO *ret = NULL, *buf = NULL, *tls = NULL;

    if ((buf = BIO_new(BIO_f_buffer())) == NULL)
        return NULL;
    if ((tls = BIO_new_tls_connect(ctx)) == NULL)
        goto err;
    if ((ret = BIO_push(buf, tls)) == NULL)
        goto err;
    return ret;
 err:
    BIO_free(buf);
    BIO_free(tls);
#endif
    return NULL;
}

BIO *BIO_new_tls_connect(tls_CTX *ctx)
{
#ifndef OPENtls_NO_SOCK
    BIO *ret = NULL, *con = NULL, *tls = NULL;

    if ((con = BIO_new(BIO_s_connect())) == NULL)
        return NULL;
    if ((tls = BIO_new_tls(ctx, 1)) == NULL)
        goto err;
    if ((ret = BIO_push(tls, con)) == NULL)
        goto err;
    return ret;
 err:
    BIO_free(con);
#endif
    return NULL;
}

BIO *BIO_new_tls(tls_CTX *ctx, int client)
{
    BIO *ret;
    tls *tls;

    if ((ret = BIO_new(BIO_f_tls())) == NULL)
        return NULL;
    if ((tls = tls_new(ctx)) == NULL) {
        BIO_free(ret);
        return NULL;
    }
    if (client)
        tls_set_connect_state(tls);
    else
        tls_set_accept_state(tls);

    BIO_set_tls(ret, tls, BIO_CLOSE);
    return ret;
}

int BIO_tls_copy_session_id(BIO *t, BIO *f)
{
    BIO_tls *tdata, *fdata;
    t = BIO_find_type(t, BIO_TYPE_tls);
    f = BIO_find_type(f, BIO_TYPE_tls);
    if ((t == NULL) || (f == NULL))
        return 0;
    tdata = BIO_get_data(t);
    fdata = BIO_get_data(f);
    if ((tdata->tls == NULL) || (fdata->tls == NULL))
        return 0;
    if (!tls_copy_session_id(tdata->tls, (fdata->tls)))
        return 0;
    return 1;
}

void BIO_tls_shutdown(BIO *b)
{
    BIO_tls *bdata;

    for (; b != NULL; b = BIO_next(b)) {
        if (BIO_method_type(b) != BIO_TYPE_tls)
            continue;
        bdata = BIO_get_data(b);
        if (bdata != NULL && bdata->tls != NULL)
            tls_shutdown(bdata->tls);
    }
}
