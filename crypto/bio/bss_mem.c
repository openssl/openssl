/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_local.h"
#include "internal/cryptlib.h"

static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int dgram_mem_new(BIO *h);
static int secmem_new(BIO *h);
static int mem_free(BIO *data);
static int mem_buf_free(BIO *data);
static int mem_buf_sync(BIO *h);

static const BIO_METHOD mem_method = {
    BIO_TYPE_MEM,
    "memory buffer",
    bwrite_conv,
    mem_write,
    bread_conv,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    mem_new,
    mem_free,
    NULL,                      /* mem_callback_ctrl */
};

static const BIO_METHOD dgram_mem_method = {
    BIO_TYPE_MEM,
    "datagram memory buffer",
    bwrite_conv,
    mem_write,
    bread_conv,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    dgram_mem_new,
    mem_free,
    NULL,                      /* mem_callback_ctrl */
};

static const BIO_METHOD secmem_method = {
    BIO_TYPE_MEM,
    "secure memory buffer",
    bwrite_conv,
    mem_write,
    bread_conv,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    secmem_new,
    mem_free,
    NULL,                      /* mem_callback_ctrl */
};

struct buf_mem_dgram_st {
    char *dgram;  /* Pointer into the buffer for where the dgram starts */
    size_t dgramlen;  /* Length of the dgram */
    struct buf_mem_dgram_st *next; /* Next dgram to read */
};

/*
 * BIO memory stores buffer and read pointer
 * however the roles are different for read only BIOs.
 * In that case the readp just stores the original state
 * to be used for reset.
 */
typedef struct bio_buf_mem_st {
    struct buf_mem_st *buf;   /* allocated buffer */
    struct buf_mem_st *readp; /* read pointer */
    struct buf_mem_dgram_st *dgrams; /* linked list of dgram data */
    struct buf_mem_dgram_st *last; /* last dgram in the linked list */
    int use_dgrams;
} BIO_BUF_MEM;

/*
 * bio->num is used to hold the value to return on 'empty', if it is 0,
 * should_retry is not set
 */

const BIO_METHOD *BIO_s_mem(void)
{
    return &mem_method;
}

const BIO_METHOD *BIO_s_dgram_mem(void)
{
    return &dgram_mem_method;
}

const BIO_METHOD *BIO_s_secmem(void)
{
    return(&secmem_method);
}

BIO *BIO_new_mem_buf(const void *buf, int len)
{
    BIO *ret;
    BUF_MEM *b;
    BIO_BUF_MEM *bb;
    size_t sz;

    if (buf == NULL) {
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    sz = (len < 0) ? strlen(buf) : (size_t)len;
    if ((ret = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    bb = (BIO_BUF_MEM *)ret->ptr;
    b = bb->buf;
    /* Cast away const and trust in the MEM_RDONLY flag. */
    b->data = (void *)buf;
    b->length = sz;
    b->max = sz;
    *bb->readp = *bb->buf;
    ret->flags |= BIO_FLAGS_MEM_RDONLY;
    /* Since this is static data retrying won't help */
    ret->num = 0;
    return ret;
}

static int mem_init(BIO *bi, unsigned long flags)
{
    BIO_BUF_MEM *bb = OPENSSL_zalloc(sizeof(*bb));

    if (bb == NULL)
        return 0;
    if ((bb->buf = BUF_MEM_new_ex(flags)) == NULL) {
        OPENSSL_free(bb);
        return 0;
    }
    if ((bb->readp = OPENSSL_zalloc(sizeof(*bb->readp))) == NULL) {
        BUF_MEM_free(bb->buf);
        OPENSSL_free(bb);
        return 0;
    }
    *bb->readp = *bb->buf;
    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)bb;
    return 1;
}

static int mem_new(BIO *bi)
{
    return mem_init(bi, 0L);
}

static int dgram_mem_new(BIO *bi)
{
    BIO_BUF_MEM *bbm;

    if (!mem_init(bi, 0L))
        return 0;

    bbm = (BIO_BUF_MEM *)bi->ptr;

    bbm->use_dgrams = 1;
    bi->num = -1;

    return 1;
}

static int secmem_new(BIO *bi)
{
    return mem_init(bi, BUF_MEM_FLAG_SECURE);
}

static void clear_all_dgrams(BIO_BUF_MEM *bbm)
{
    struct buf_mem_dgram_st *dgrams = bbm->dgrams;

    while (dgrams != NULL) {
        struct buf_mem_dgram_st *tmp = dgrams;

        dgrams = dgrams->next;
        OPENSSL_free(tmp);
    }
    bbm->dgrams = NULL;
}

static int mem_free(BIO *a)
{
    BIO_BUF_MEM *bb;

    if (a == NULL)
        return 0;

    bb = (BIO_BUF_MEM *)a->ptr;
    if (!mem_buf_free(a))
        return 0;
    OPENSSL_free(bb->readp);
    clear_all_dgrams(bb);
    OPENSSL_free(bb);
    return 1;
}

static int mem_buf_free(BIO *a)
{
    if (a == NULL)
        return 0;

    if (a->shutdown && a->init && a->ptr != NULL) {
        BIO_BUF_MEM *bb = (BIO_BUF_MEM *)a->ptr;
        BUF_MEM *b = bb->buf;

        if (a->flags & BIO_FLAGS_MEM_RDONLY)
            b->data = NULL;
        BUF_MEM_free(b);
    }
    return 1;
}

/*
 * Reallocate memory buffer if read pointer differs
 * NOT FOR RDONLY
 */
static int mem_buf_sync(BIO *b)
{
    if (b != NULL && b->init != 0 && b->ptr != NULL) {
        BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

        if (bbm->readp->data != bbm->buf->data) {
            memmove(bbm->buf->data, bbm->readp->data, bbm->readp->length);
            bbm->buf->length = bbm->readp->length;
            bbm->readp->data = bbm->buf->data;
        }
    }
    return 0;
}

static int mem_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm = bbm->readp;
    size_t maxreadlen = 0;
    int eof = 0;

    if (b->flags & BIO_FLAGS_MEM_RDONLY)
        bm = bbm->buf;
    BIO_clear_retry_flags(b);
    if (bbm->use_dgrams) {
        if (bbm->dgrams != NULL) {
            maxreadlen = bbm->dgrams->dgramlen;
            if (!ossl_assert(maxreadlen <= bm->length))
                return 0;
        } else {
            eof = 1;
        }
    } else {
        maxreadlen = bm->length;
        eof = (maxreadlen == 0);
    }
    ret = (outl >= 0 && (size_t)outl > maxreadlen) ? (int)maxreadlen : outl;
    if ((out != NULL) && (ret > 0)) {
        size_t flushlen;

        memcpy(out, bm->data, ret);
        flushlen = bbm->use_dgrams ? maxreadlen : (size_t)ret;
            
        bm->length -= flushlen;
        bm->max -= flushlen;
        bm->data += flushlen;
        if (bbm->use_dgrams) {
            struct buf_mem_dgram_st *tmp = bbm->dgrams;

            bbm->dgrams = tmp->next;
            OPENSSL_free(tmp);
            if (bbm->dgrams == NULL)
                bbm->last = NULL;
        }
    } else if (eof) {
        ret = b->num;
        if (ret != 0)
            BIO_set_retry_read(b);
    }
    return ret;
}

static int mem_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    int blen;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

    if (b->flags & BIO_FLAGS_MEM_RDONLY) {
        ERR_raise(ERR_LIB_BIO, BIO_R_WRITE_TO_READ_ONLY_BIO);
        goto end;
    }
    BIO_clear_retry_flags(b);

    if (inl == 0)
        return 0;

    if (in == NULL) {
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }
    blen = bbm->readp->length;
    mem_buf_sync(b);
    if (BUF_MEM_grow_clean(bbm->buf, blen + inl) == 0)
        goto end;

    memcpy(bbm->buf->data + blen, in, inl);
    *bbm->readp = *bbm->buf;

    if (bbm->use_dgrams) {
        struct buf_mem_dgram_st *dgram = OPENSSL_malloc(sizeof(*dgram));

        if (dgram == NULL)
            goto end;

        dgram->dgram = bbm->buf->data + blen;
        dgram->dgramlen = inl;
        dgram->next = NULL;
        if (bbm->dgrams == NULL)
            bbm->dgrams = dgram;
        else
            bbm->last->next = dgram;
        bbm->last = dgram;
    }

    ret = inl;
 end:
    return ret;
}

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm, *bo;            /* bio_mem, bio_other */
    long off, remain;

    if (b->flags & BIO_FLAGS_MEM_RDONLY) {
        bm = bbm->buf;
        bo = bbm->readp;
    } else {
        bm = bbm->readp;
        bo = bbm->buf;
    }
    off = (bm->data == bo->data) ? 0 : bm->data - bo->data;
    remain = bm->length;

    switch (cmd) {
    case BIO_CTRL_RESET:
        bm = bbm->buf;
        if (bm->data != NULL) {
            if (!(b->flags & BIO_FLAGS_MEM_RDONLY)) {
                if (!(b->flags & BIO_FLAGS_NONCLEAR_RST)) {
                    memset(bm->data, 0, bm->max);
                    bm->length = 0;
                }
                *bbm->readp = *bbm->buf;
            } else {
                /* For read only case just reset to the start again */
                *bbm->buf = *bbm->readp;
            }
        }
        clear_all_dgrams(bbm);
        break;
    case BIO_C_FILE_SEEK:
        if (num < 0 || num > off + remain)
            return -1;   /* Can't see outside of the current buffer */

        bm->data = (num != 0) ? bo->data + num : bo->data;
        bm->length = bo->length - num;
        bm->max = bo->max - num;
        off = num;
        /* FALLTHRU */
    case BIO_C_FILE_TELL:
        ret = off;
        break;
    case BIO_CTRL_EOF:
        ret = (long)(bm->length == 0 && bbm->use_dgrams == 0);
        break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        if (!bbm->use_dgrams)
            b->num = (int)num;
        else
            ret = -1;
        break;
    case BIO_CTRL_INFO:
        ret = (long)bm->length;
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)(bm->data);
        }
        break;
    case BIO_C_SET_BUF_MEM:
        mem_buf_free(b);
        b->shutdown = (int)num;
        bbm->buf = ptr;
        *bbm->readp = *bbm->buf;
        break;
    case BIO_C_GET_BUF_MEM_PTR:
        if (ptr != NULL) {
            if (!(b->flags & BIO_FLAGS_MEM_RDONLY))
                mem_buf_sync(b);
            bm = bbm->buf;
            pptr = (char **)ptr;
            *pptr = (char *)bm;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_WPENDING:
        ret = 0L;
        break;
    case BIO_CTRL_PENDING:
        ret = (long)bm->length;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int mem_gets(BIO *bp, char *buf, int size)
{
    int i, j;
    int ret = -1;
    char *p;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)bp->ptr;
    BUF_MEM *bm = bbm->readp;

    if (bp->flags & BIO_FLAGS_MEM_RDONLY)
        bm = bbm->buf;
    BIO_clear_retry_flags(bp);
    j = (!bbm->use_dgrams || bbm->dgrams == NULL) ? bm->length
                                                  : bbm->dgrams->dgramlen;
    if ((size - 1) < j)
        j = size - 1;
    if (j <= 0) {
        *buf = '\0';
        return 0;
    }
    p = bm->data;
    for (i = 0; i < j; i++) {
        if (p[i] == '\n') {
            i++;
            break;
        }
    }

    /*
     * i is now the max num of bytes to copy, either j or up to
     * and including the first newline
     */

    i = mem_read(bp, buf, i);
    if (i > 0)
        buf[i] = '\0';
    ret = i;
    return ret;
}

static int mem_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = mem_write(bp, str, n);
    /* memory semantics is that it will always work */
    return ret;
}
