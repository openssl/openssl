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
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "internal/cryptlib.h"
#include "internal/threads.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# include <execinfo.h>
#endif

/*
 * The state changes to CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE when
 * the application asks for it (usually after library initialisation for
 * which no book-keeping is desired). State CRYPTO_MEM_CHECK_ON exists only
 * temporarily when the library thinks that certain allocations should not be
 * checked (e.g. the data structures used for memory checking).  It is not
 * suitable as an initial state: the library will unexpectedly enable memory
 * checking when it executes one of those sections that want to disable
 * checking temporarily. State CRYPTO_MEM_CHECK_ENABLE without ..._ON makes
 * no sense whatsoever.
 */
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static int mh_mode = CRYPTO_MEM_CHECK_OFF;
#endif

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static unsigned long order = 0; /* number of memory requests */

/*-
 * For application-defined information (static C-string `info')
 * to be displayed in memory leak list.
 * Each thread has its own stack.  For applications, there is
 *   OPENSSL_mem_debug_push("...")     to push an entry,
 *   OPENSSL_mem_debug_pop()     to pop an entry,
 */
struct app_mem_info_st {
    CRYPTO_THREAD_ID threadid;
    const char *file;
    int line;
    const char *info;
    struct app_mem_info_st *next; /* tail of thread's stack */
    int references;
};

static CRYPTO_ONCE memdbg_init = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *malloc_lock = NULL;
static CRYPTO_RWLOCK *long_malloc_lock = NULL;
static CRYPTO_THREAD_LOCAL appinfokey;

/* memory-block description */
struct mem_st {
    void *addr;
    int num;
    const char *file;
    int line;
    CRYPTO_THREAD_ID threadid;
    unsigned long order;
    time_t time;
    APP_INFO *app_info;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
    void *array[30];
    size_t array_siz;
#endif
};

static LHASH_OF(MEM) *mh = NULL; /* hash-table of memory requests (address as
                                  * key); access requires MALLOC2 lock */

/* num_disable > 0 iff mh_mode == CRYPTO_MEM_CHECK_ON (w/o ..._ENABLE) */
static unsigned int num_disable = 0;

/*
 * Valid iff num_disable > 0.  long_malloc_lock is locked exactly in this
 * case (by the thread named in disabling_thread).
 */
static CRYPTO_THREAD_ID disabling_threadid;

static void do_memdbg_init(void)
{
    malloc_lock = CRYPTO_THREAD_lock_new();
    long_malloc_lock = CRYPTO_THREAD_lock_new();
    CRYPTO_THREAD_init_local(&appinfokey, NULL);
}

static void app_info_free(APP_INFO *inf)
{
    if (!inf)
        return;
    if (--(inf->references) <= 0) {
        app_info_free(inf->next);
        OPENSSL_free(inf);
    }
}
#endif

int CRYPTO_mem_ctrl(int mode)
{
#ifdef OPENSSL_NO_CRYPTO_MDEBUG
    return mode - mode;
#else
    int ret = mh_mode;

    CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);

    CRYPTO_THREAD_write_lock(malloc_lock);
    switch (mode) {
    default:
        break;

    case CRYPTO_MEM_CHECK_ON:
        mh_mode = CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE;
        num_disable = 0;
        break;

    case CRYPTO_MEM_CHECK_OFF:
        mh_mode = 0;
        num_disable = 0;
        break;

    /* switch off temporarily (for library-internal use): */
    case CRYPTO_MEM_CHECK_DISABLE:
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            CRYPTO_THREAD_ID cur = CRYPTO_THREAD_get_current_id();
            /* see if we don't have long_malloc_lock already */
            if (!num_disable
                || !CRYPTO_THREAD_compare_id(disabling_threadid, cur)) {
                /*
                 * Long-time lock long_malloc_lock must not be claimed
                 * while we're holding malloc_lock, or we'll deadlock
                 * if somebody else holds long_malloc_lock (and cannot
                 * release it because we block entry to this function). Give
                 * them a chance, first, and then claim the locks in
                 * appropriate order (long-time lock first).
                 */
                CRYPTO_THREAD_unlock(malloc_lock);
                /*
                 * Note that after we have waited for long_malloc_lock and
                 * malloc_lock, we'll still be in the right "case" and
                 * "if" branch because MemCheck_start and MemCheck_stop may
                 * never be used while there are multiple OpenSSL threads.
                 */
                CRYPTO_THREAD_write_lock(long_malloc_lock);
                CRYPTO_THREAD_write_lock(malloc_lock);
                mh_mode &= ~CRYPTO_MEM_CHECK_ENABLE;
                disabling_threadid = cur;
            }
            num_disable++;
        }
        break;

    case CRYPTO_MEM_CHECK_ENABLE:
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            if (num_disable) {  /* always true, or something is going wrong */
                num_disable--;
                if (num_disable == 0) {
                    mh_mode |= CRYPTO_MEM_CHECK_ENABLE;
                    CRYPTO_THREAD_unlock(long_malloc_lock);
                }
            }
        }
        break;
    }
    CRYPTO_THREAD_unlock(malloc_lock);
    return (ret);
#endif
}

#ifndef OPENSSL_NO_CRYPTO_MDEBUG

static int mem_check_on(void)
{
    int ret = 0;
    CRYPTO_THREAD_ID cur;

    if (mh_mode & CRYPTO_MEM_CHECK_ON) {
        CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);

        cur = CRYPTO_THREAD_get_current_id();
        CRYPTO_THREAD_read_lock(malloc_lock);

        ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
            || !CRYPTO_THREAD_compare_id(disabling_threadid, cur);

        CRYPTO_THREAD_unlock(malloc_lock);
    }
    return (ret);
}

static int mem_cmp(const MEM *a, const MEM *b)
{
#ifdef _WIN64
    const char *ap = (const char *)a->addr, *bp = (const char *)b->addr;
    if (ap == bp)
        return 0;
    else if (ap > bp)
        return 1;
    else
        return -1;
#else
    return (const char *)a->addr - (const char *)b->addr;
#endif
}

static unsigned long mem_hash(const MEM *a)
{
    size_t ret;

    ret = (size_t)a->addr;

    ret = ret * 17851 + (ret >> 14) * 7 + (ret >> 4) * 251;
    return (ret);
}

/* returns 1 if there was an info to pop, 0 if the stack was empty. */
static int pop_info(void)
{
    APP_INFO *current = NULL;

    CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);
    current = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
    if (current != NULL) {
        APP_INFO *next = current->next;

        if (next != NULL) {
            next->references++;
            CRYPTO_THREAD_set_local(&appinfokey, next);
        } else {
            CRYPTO_THREAD_set_local(&appinfokey, NULL);
        }
        if (--(current->references) <= 0) {
            current->next = NULL;
            if (next != NULL)
                next->references--;
            OPENSSL_free(current);
        }
        return 1;
    }
    return 0;
}

int CRYPTO_mem_debug_push(const char *info, const char *file, int line)
{
    APP_INFO *ami, *amim;
    int ret = 0;

    if (mem_check_on()) {
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

        CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);

        if ((ami = OPENSSL_malloc(sizeof(*ami))) == NULL)
            goto err;

        ami->threadid = CRYPTO_THREAD_get_current_id();
        ami->file = file;
        ami->line = line;
        ami->info = info;
        ami->references = 1;
        ami->next = NULL;

        amim = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
        CRYPTO_THREAD_set_local(&appinfokey, ami);

        if (amim != NULL)
            ami->next = amim;
        ret = 1;
 err:
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
    }

    return (ret);
}

int CRYPTO_mem_debug_pop(void)
{
    int ret = 0;

    if (mem_check_on()) {
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
        ret = pop_info();
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
    }
    return (ret);
}

static unsigned long break_order_num = 0;

void CRYPTO_mem_debug_malloc(void *addr, size_t num, int before_p,
                             const char *file, int line)
{
    MEM *m, *mm;
    APP_INFO *amim;

    switch (before_p & 127) {
    case 0:
        break;
    case 1:
        if (addr == NULL)
            break;

        if (mem_check_on()) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

            CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);

            if ((m = OPENSSL_malloc(sizeof(*m))) == NULL) {
                OPENSSL_free(addr);
                CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
                return;
            }
            if (mh == NULL) {
                if ((mh = lh_MEM_new(mem_hash, mem_cmp)) == NULL) {
                    OPENSSL_free(addr);
                    OPENSSL_free(m);
                    addr = NULL;
                    goto err;
                }
            }

            m->addr = addr;
            m->file = file;
            m->line = line;
            m->num = num;
            m->threadid = CRYPTO_THREAD_get_current_id();

            if (order == break_order_num) {
                /* BREAK HERE */
                m->order = order;
            }
            m->order = order++;
# ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
            m->array_siz = backtrace(m->array, OSSL_NELEM(m->array));
# endif
            m->time = time(NULL);

            amim = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
            m->app_info = amim;
            if (amim != NULL)
                amim->references++;

            if ((mm = lh_MEM_insert(mh, m)) != NULL) {
                /* Not good, but don't sweat it */
                if (mm->app_info != NULL) {
                    mm->app_info->references--;
                }
                OPENSSL_free(mm);
            }
 err:
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        }
        break;
    }
    return;
}

void CRYPTO_mem_debug_free(void *addr, int before_p,
        const char *file, int line)
{
    MEM m, *mp;

    switch (before_p) {
    case 0:
        if (addr == NULL)
            break;

        if (mem_check_on() && (mh != NULL)) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

            m.addr = addr;
            mp = lh_MEM_delete(mh, &m);
            if (mp != NULL) {
                app_info_free(mp->app_info);
                OPENSSL_free(mp);
            }

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        }
        break;
    case 1:
        break;
    }
}

void CRYPTO_mem_debug_realloc(void *addr1, void *addr2, size_t num,
                              int before_p, const char *file, int line)
{
    MEM m, *mp;

    switch (before_p) {
    case 0:
        break;
    case 1:
        if (addr2 == NULL)
            break;

        if (addr1 == NULL) {
            CRYPTO_mem_debug_malloc(addr2, num, 128 | before_p, file, line);
            break;
        }

        if (mem_check_on()) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

            m.addr = addr1;
            mp = lh_MEM_delete(mh, &m);
            if (mp != NULL) {
                mp->addr = addr2;
                mp->num = num;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
                mp->array_siz = backtrace(mp->array, OSSL_NELEM(mp->array));
#endif
                (void)lh_MEM_insert(mh, mp);
            }

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
        }
        break;
    }
    return;
}

typedef struct mem_leak_st {
    BIO *bio;
    int chunks;
    long bytes;
} MEM_LEAK;

static void print_leak(const MEM *m, MEM_LEAK *l)
{
    char buf[1024];
    char *bufp = buf;
    APP_INFO *amip;
    int ami_cnt;
    struct tm *lcl = NULL;
    /*
     * Convert between CRYPTO_THREAD_ID (which could be anything at all) and
     * a long. This may not be meaningful depending on what CRYPTO_THREAD_ID is
     * but hopefully should give something sensible on most platforms
     */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;
    CRYPTO_THREAD_ID ti;

#define BUF_REMAIN (sizeof buf - (size_t)(bufp - buf))

    lcl = localtime(&m->time);
    BIO_snprintf(bufp, BUF_REMAIN, "[%02d:%02d:%02d] ",
                 lcl->tm_hour, lcl->tm_min, lcl->tm_sec);
    bufp += strlen(bufp);

    BIO_snprintf(bufp, BUF_REMAIN, "%5lu file=%s, line=%d, ",
                 m->order, m->file, m->line);
    bufp += strlen(bufp);

    tid.ltid = 0;
    tid.tid = m->threadid;
    BIO_snprintf(bufp, BUF_REMAIN, "thread=%lu, ", tid.ltid);
    bufp += strlen(bufp);

    BIO_snprintf(bufp, BUF_REMAIN, "number=%d, address=%p\n",
                 m->num, m->addr);
    bufp += strlen(bufp);

    BIO_puts(l->bio, buf);

    l->chunks++;
    l->bytes += m->num;

    amip = m->app_info;
    ami_cnt = 0;

    if (amip) {
        ti = amip->threadid;

        do {
            int buf_len;
            int info_len;

            ami_cnt++;
            memset(buf, '>', ami_cnt);
            tid.ltid = 0;
            tid.tid = amip->threadid;
            BIO_snprintf(buf + ami_cnt, sizeof buf - ami_cnt,
                         " thread=%lu, file=%s, line=%d, info=\"",
                         tid.ltid, amip->file,
                         amip->line);
            buf_len = strlen(buf);
            info_len = strlen(amip->info);
            if (128 - buf_len - 3 < info_len) {
                memcpy(buf + buf_len, amip->info, 128 - buf_len - 3);
                buf_len = 128 - 3;
            } else {
                OPENSSL_strlcpy(buf + buf_len, amip->info, sizeof buf - buf_len);
                buf_len = strlen(buf);
            }
            BIO_snprintf(buf + buf_len, sizeof buf - buf_len, "\"\n");

            BIO_puts(l->bio, buf);

            amip = amip->next;
        }
        while (amip && CRYPTO_THREAD_compare_id(amip->threadid, ti));
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
    {
        size_t i;
        char **strings = backtrace_symbols(m->array, m->array_siz);

        for (i = 0; i < m->array_siz; i++)
            fprintf(stderr, "##> %s\n", strings[i]);
        free(strings);
    }
#endif
}

IMPLEMENT_LHASH_DOALL_ARG_CONST(MEM, MEM_LEAK);

int CRYPTO_mem_leaks(BIO *b)
{
    MEM_LEAK ml;

    /* Ensure all resources are released */
    OPENSSL_cleanup();

    CRYPTO_THREAD_run_once(&memdbg_init, do_memdbg_init);

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

    ml.bio = b;
    ml.bytes = 0;
    ml.chunks = 0;
    if (mh != NULL)
        lh_MEM_doall_MEM_LEAK(mh, print_leak, &ml);

    if (ml.chunks != 0) {
        BIO_printf(b, "%ld bytes leaked in %d chunks\n", ml.bytes, ml.chunks);
    } else {
        /*
         * Make sure that, if we found no leaks, memory-leak debugging itself
         * does not introduce memory leaks (which might irritate external
         * debugging tools). (When someone enables leak checking, but does not
         * call this function, we declare it to be their fault.)
         */
        int old_mh_mode;

        CRYPTO_THREAD_write_lock(malloc_lock);

        /*
         * avoid deadlock when lh_free() uses CRYPTO_mem_debug_free(), which uses
         * mem_check_on
         */
        old_mh_mode = mh_mode;
        mh_mode = CRYPTO_MEM_CHECK_OFF;

        lh_MEM_free(mh);
        mh = NULL;

        mh_mode = old_mh_mode;
        CRYPTO_THREAD_unlock(malloc_lock);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);

    /* Clean up locks etc */
    CRYPTO_THREAD_cleanup_local(&appinfokey);
    CRYPTO_THREAD_lock_free(malloc_lock);
    CRYPTO_THREAD_lock_free(long_malloc_lock);
    malloc_lock = NULL;
    long_malloc_lock = NULL;

    return ml.chunks == 0 ? 1 : 0;
}

# ifndef OPENSSL_NO_STDIO
int CRYPTO_mem_leaks_fp(FILE *fp)
{
    BIO *b;
    int ret;

    /*
     * Need to turn off memory checking when allocated BIOs ... especially as
     * we're creating them at a time when we're trying to check we've not
     * left anything un-free()'d!!
     */
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
    b = BIO_new(BIO_s_file());
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
    if (b == NULL)
        return -1;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = CRYPTO_mem_leaks(b);
    BIO_free(b);
    return ret;
}
# endif

#endif
