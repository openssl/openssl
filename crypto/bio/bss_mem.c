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

#include <stdio.h>
#include <errno.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"

static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int secmem_new(BIO *h);
static int mem_free(BIO *data);
static int mem_buf_free(BIO *data, int free_all);
static int mem_buf_sync(BIO *h);

static const BIO_METHOD mem_method = {
    BIO_TYPE_MEM,
    "memory buffer",
    mem_write,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    mem_new,
    mem_free,
    NULL,
};

static const BIO_METHOD secmem_method = {
    BIO_TYPE_MEM,
    "secure memory buffer",
    mem_write,
    mem_read,
    mem_puts,
    mem_gets,
    mem_ctrl,
    secmem_new,
    mem_free,
    NULL,
};

/* BIO memory stores buffer and read pointer  */
typedef struct bio_buf_mem_st {
    struct buf_mem_st *buf;   /* allocated buffer */
    struct buf_mem_st *readp; /* read pointer */
} BIO_BUF_MEM;

/*
 * bio->num is used to hold the value to return on 'empty', if it is 0,
 * should_retry is not set
 */

const BIO_METHOD *BIO_s_mem(void)
{
    return (&mem_method);
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
        BIOerr(BIO_F_BIO_NEW_MEM_BUF, BIO_R_NULL_PARAMETER);
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
    /* Since this is static data retrying wont help */
    ret->num = 0;
    return ret;
}

static int mem_init(BIO *bi, unsigned long flags)
{
    BIO_BUF_MEM *bb = OPENSSL_zalloc(sizeof(*bb));

    if (bb == NULL)
        return(0);
    if ((bb->buf = BUF_MEM_new_ex(flags)) == NULL)
        return(0);
    if ((bb->readp = OPENSSL_zalloc(sizeof(*bb->readp))) == NULL)
        return(0);
    *bb->readp = *bb->buf;
    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)bb;
    return(1);
}

static int mem_new(BIO *bi)
{
    return (mem_init(bi, 0L));
}

static int secmem_new(BIO *bi)
{
    return (mem_init(bi, BUF_MEM_FLAG_SECURE));
}

static int mem_free(BIO *a)
{
    return (mem_buf_free(a, 1));
}

static int mem_buf_free(BIO *a, int free_all)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            BUF_MEM *b;
            BIO_BUF_MEM *bb = (BIO_BUF_MEM *)a->ptr;

            if(bb != NULL) {
                b = bb->buf;
                if (a->flags & BIO_FLAGS_MEM_RDONLY)
                    b->data = NULL;
                BUF_MEM_free(b);
                if(free_all) {
                    OPENSSL_free(bb->readp);
                    OPENSSL_free(bb);
                }
            }
            a->ptr = NULL;
        }
    }
    return (1);
}

/*
 * Reallocate memory buffer if read pointer differs
 */
static int mem_buf_sync(BIO *b)
{
    if((b != NULL) && (b->init) && (b->ptr != NULL)) {
        BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

        if(bbm->readp->data != bbm->buf->data) {
            memmove(bbm->buf->data, bbm->readp->data, bbm->readp->length);
            bbm->buf->length = bbm->readp->length;
            bbm->readp->data = bbm->buf->data;
        }
    }
    return (0);
}

static int mem_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm = bbm->readp;

    BIO_clear_retry_flags(b);
    ret = (outl >= 0 && (size_t)outl > bm->length) ? (int)bm->length : outl;
    if ((out != NULL) && (ret > 0)) {
        memcpy(out, bm->data, ret);
        bm->length -= ret;
        bm->data += ret;
    } else if (bm->length == 0) {
        ret = b->num;
        if (ret != 0)
            BIO_set_retry_read(b);
    }
    return (ret);
}

static int mem_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    int blen;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

    if (in == NULL) {
        BIOerr(BIO_F_MEM_WRITE, BIO_R_NULL_PARAMETER);
        goto end;
    }
    if (b->flags & BIO_FLAGS_MEM_RDONLY) {
        BIOerr(BIO_F_MEM_WRITE, BIO_R_WRITE_TO_READ_ONLY_BIO);
        goto end;
    }
    BIO_clear_retry_flags(b);
    blen = bbm->readp->length;
    mem_buf_sync(b);
    if (BUF_MEM_grow_clean(bbm->buf, blen + inl) == 0)
        goto end;
    memcpy(bbm->buf->data + blen, in, inl);
    *bbm->readp = *bbm->buf;
    ret = inl;
 end:
    return (ret);
}

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm;

    switch (cmd) {
    case BIO_CTRL_RESET:
        bm = bbm->buf;
        if (bm->data != NULL) {
            /* For read only case reset to the start again */
            if ((b->flags & BIO_FLAGS_MEM_RDONLY) || (b->flags & BIO_FLAGS_NONCLEAR_RST)) {
                bm->length = bm->max;
            } else {
                memset(bm->data, 0, bm->max);
                bm->length = 0;
            }
            *bbm->readp = *bbm->buf;
        }
        break;
    case BIO_CTRL_EOF:
        bm = bbm->readp;
        ret = (long)(bm->length == 0);
        break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        b->num = (int)num;
        break;
    case BIO_CTRL_INFO:
        bm = bbm->readp;
        ret = (long)bm->length;
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)&(bm->data[0]);
        }
        break;
    case BIO_C_SET_BUF_MEM:
        mem_buf_free(b, 0);
        b->shutdown = (int)num;
        bbm->buf = ptr;
        *bbm->readp = *bbm->buf;
        b->ptr = bbm;
        break;
    case BIO_C_GET_BUF_MEM_PTR:
        if (ptr != NULL) {
            mem_buf_sync(b);
            bm = bbm->readp;
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
        bm = bbm->readp;
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
    return (ret);
}

static int mem_gets(BIO *bp, char *buf, int size)
{
    int i, j;
    int ret = -1;
    char *p;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)bp->ptr;
    BUF_MEM *bm = bbm->readp;

    BIO_clear_retry_flags(bp);
    j = bm->length;
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
    return (ret);
}

static int mem_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = mem_write(bp, str, n);
    /* memory semantics is that it will always work */
    return (ret);
}
