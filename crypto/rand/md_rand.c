/* crypto/rand/md_rand.c */
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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#ifdef MD_RAND_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "e_os.h"

#if !(defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_DSPBIOS))
# include <sys/time.h>
#endif
#if defined(OPENSSL_SYS_VXWORKS)
# include <time.h>
#endif

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/async.h>
#include "rand_lcl.h"

#include <openssl/err.h>

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

#ifdef BN_DEBUG
# define PREDICT
#endif

/* #define PREDICT      1 */

#define STATE_SIZE      1023
static int state_num = 0, state_index = 0;
static unsigned char state[STATE_SIZE + MD_DIGEST_LENGTH];
static unsigned char md[MD_DIGEST_LENGTH];
static long md_count[2] = { 0, 0 };

static double entropy = 0;
static int initialized = 0;

static unsigned int crypto_lock_rand = 0; /* may be set only when a thread
                                           * holds CRYPTO_LOCK_RAND (to
                                           * prevent double locking) */
/* access to lockin_thread is synchronized by CRYPTO_LOCK_RAND2 */
/* valid iff crypto_lock_rand is set */
static CRYPTO_THREADID locking_threadid;

#ifdef PREDICT
int rand_predictable = 0;
#endif

static void rand_hw_seed(EVP_MD_CTX *ctx);

static void rand_cleanup(void);
static int rand_seed(const void *buf, int num);
static int rand_add(const void *buf, int num, double add_entropy);
static int rand_bytes(unsigned char *buf, int num, int pseudo);
static int rand_nopseudo_bytes(unsigned char *buf, int num);
#ifndef OPENSSL_NO_DEPRECATED
static int rand_pseudo_bytes(unsigned char *buf, int num);
#endif
static int rand_status(void);

static RAND_METHOD rand_meth = {
    rand_seed,
    rand_nopseudo_bytes,
    rand_cleanup,
    rand_add,
#ifndef OPENSSL_NO_DEPRECATED
    rand_pseudo_bytes,
#else
    NULL,
#endif
    rand_status
};

RAND_METHOD *RAND_OpenSSL(void)
{
    return (&rand_meth);
}

static void rand_cleanup(void)
{
    OPENSSL_cleanse(state, sizeof(state));
    state_num = 0;
    state_index = 0;
    OPENSSL_cleanse(md, MD_DIGEST_LENGTH);
    md_count[0] = 0;
    md_count[1] = 0;
    entropy = 0;
    initialized = 0;
}

static int rand_add(const void *buf, int num, double add)
{
    int i, j, k, st_idx;
    long md_c[2];
    unsigned char local_md[MD_DIGEST_LENGTH];
    EVP_MD_CTX m;
    int do_not_lock;
    int rv = 0;

    if (!num)
        return 1;

    /*
     * (Based on the rand(3) manpage)
     *
     * The input is chopped up into units of 20 bytes (or less for
     * the last block).  Each of these blocks is run through the hash
     * function as follows:  The data passed to the hash function
     * is the current 'md', the same number of bytes from the 'state'
     * (the location determined by in incremented looping index) as
     * the current 'block', the new key data 'block', and 'count'
     * (which is incremented after each use).
     * The result of this is kept in 'md' and also xored into the
     * 'state' at the same locations that were used as input into the
     * hash function.
     */

    EVP_MD_CTX_init(&m);
    /* check if we already have the lock */
    if (crypto_lock_rand) {
        CRYPTO_THREADID cur;
        CRYPTO_THREADID_current(&cur);
        CRYPTO_r_lock(CRYPTO_LOCK_RAND2);
        do_not_lock = !CRYPTO_THREADID_cmp(&locking_threadid, &cur);
        CRYPTO_r_unlock(CRYPTO_LOCK_RAND2);
    } else
        do_not_lock = 0;

    if (!do_not_lock)
        CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    st_idx = state_index;

    /*
     * use our own copies of the counters so that even if a concurrent thread
     * seeds with exactly the same data and uses the same subarray there's
     * _some_ difference
     */
    md_c[0] = md_count[0];
    md_c[1] = md_count[1];

    memcpy(local_md, md, sizeof md);

    /* state_index <= state_num <= STATE_SIZE */
    state_index += num;
    if (state_index >= STATE_SIZE) {
        state_index %= STATE_SIZE;
        state_num = STATE_SIZE;
    } else if (state_num < STATE_SIZE) {
        if (state_index > state_num)
            state_num = state_index;
    }
    /* state_index <= state_num <= STATE_SIZE */

    /*
     * state[st_idx], ..., state[(st_idx + num - 1) % STATE_SIZE] are what we
     * will use now, but other threads may use them as well
     */

    md_count[1] += (num / MD_DIGEST_LENGTH) + (num % MD_DIGEST_LENGTH > 0);

    if (!do_not_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    for (i = 0; i < num; i += MD_DIGEST_LENGTH) {
        j = (num - i);
        j = (j > MD_DIGEST_LENGTH) ? MD_DIGEST_LENGTH : j;

        if (!MD_Init(&m))
            goto err;
        if (!MD_Update(&m, local_md, MD_DIGEST_LENGTH))
            goto err;
        k = (st_idx + j) - STATE_SIZE;
        if (k > 0) {
            if (!MD_Update(&m, &(state[st_idx]), j - k))
                goto err;
            if (!MD_Update(&m, &(state[0]), k))
                goto err;
        } else if (!MD_Update(&m, &(state[st_idx]), j))
            goto err;

        /* DO NOT REMOVE THE FOLLOWING CALL TO MD_Update()! */
        if (!MD_Update(&m, buf, j))
            goto err;
        /*
         * We know that line may cause programs such as purify and valgrind
         * to complain about use of uninitialized data.  The problem is not,
         * it's with the caller.  Removing that line will make sure you get
         * really bad randomness and thereby other problems such as very
         * insecure keys.
         */

        if (!MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c)))
            goto err;
        if (!MD_Final(&m, local_md))
            goto err;
        md_c[1]++;

        buf = (const char *)buf + j;

        for (k = 0; k < j; k++) {
            /*
             * Parallel threads may interfere with this, but always each byte
             * of the new state is the XOR of some previous value of its and
             * local_md (itermediate values may be lost). Alway using locking
             * could hurt performance more than necessary given that
             * conflicts occur only when the total seeding is longer than the
             * random state.
             */
            state[st_idx++] ^= local_md[k];
            if (st_idx >= STATE_SIZE)
                st_idx = 0;
        }
    }

    if (!do_not_lock)
        CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    /*
     * Don't just copy back local_md into md -- this could mean that other
     * thread's seeding remains without effect (except for the incremented
     * counter).  By XORing it we keep at least as much entropy as fits into
     * md.
     */
    for (k = 0; k < (int)sizeof(md); k++) {
        md[k] ^= local_md[k];
    }
    if (entropy < ENTROPY_NEEDED) /* stop counting when we have enough */
        entropy += add;
    if (!do_not_lock)
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

#if !defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32)
    assert(md_c[1] == md_count[1]);
#endif
    rv = 1;
 err:
    EVP_MD_CTX_cleanup(&m);
    return rv;
}

static int rand_seed(const void *buf, int num)
{
    return rand_add(buf, num, (double)num);
}

static int rand_bytes(unsigned char *buf, int num, int pseudo)
{
    static volatile int stirred_pool = 0;
    int i, j, k, st_num, st_idx;
    int num_ceil;
    int ok;
    long md_c[2];
    unsigned char local_md[MD_DIGEST_LENGTH];
    EVP_MD_CTX m;
#ifndef GETPID_IS_MEANINGLESS
    pid_t curr_pid = getpid();
#endif
    time_t curr_time = time(NULL);
    int do_stir_pool = 0;
/* time value for various platforms */
#ifdef OPENSSL_SYS_WIN32
    FILETIME tv;
# ifdef _WIN32_WCE
    SYSTEMTIME t;
    GetSystemTime(&t);
    SystemTimeToFileTime(&t, &tv);
# else
    GetSystemTimeAsFileTime(&tv);
# endif
#elif defined(OPENSSL_SYS_VXWORKS)
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &ts);
#elif defined(OPENSSL_SYS_DSPBIOS)
    unsigned long long tv, OPENSSL_rdtsc();
    tv = OPENSSL_rdtsc();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
#endif

#ifdef PREDICT
    if (rand_predictable) {
        static unsigned char val = 0;

        for (i = 0; i < num; i++)
            buf[i] = val++;
        return (1);
    }
#endif

    if (num <= 0)
        return 1;

    EVP_MD_CTX_init(&m);
    /* round upwards to multiple of MD_DIGEST_LENGTH/2 */
    num_ceil =
        (1 + (num - 1) / (MD_DIGEST_LENGTH / 2)) * (MD_DIGEST_LENGTH / 2);

    /*
     * (Based on the rand(3) manpage:)
     *
     * For each group of 10 bytes (or less), we do the following:
     *
     * Input into the hash function the local 'md' (which is initialized from
     * the global 'md' before any bytes are generated), the bytes that are to
     * be overwritten by the random bytes, and bytes from the 'state'
     * (incrementing looping index). From this digest output (which is kept
     * in 'md'), the top (up to) 10 bytes are returned to the caller and the
     * bottom 10 bytes are xored into the 'state'.
     *
     * Finally, after we have finished 'num' random bytes for the
     * caller, 'count' (which is incremented) and the local and global 'md'
     * are fed into the hash function and the results are kept in the
     * global 'md'.
     */

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    /*
     * We could end up in an async engine while holding this lock so ensure
     * we don't pause and cause a deadlock
     */
    ASYNC_block_pause();

    /* prevent rand_bytes() from trying to obtain the lock again */
    CRYPTO_w_lock(CRYPTO_LOCK_RAND2);
    CRYPTO_THREADID_current(&locking_threadid);
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND2);
    crypto_lock_rand = 1;

    if (!initialized) {
        RAND_poll();
        initialized = 1;
    }

    if (!stirred_pool)
        do_stir_pool = 1;

    ok = (entropy >= ENTROPY_NEEDED);
    if (!ok) {
        /*
         * If the PRNG state is not yet unpredictable, then seeing the PRNG
         * output may help attackers to determine the new state; thus we have
         * to decrease the entropy estimate. Once we've had enough initial
         * seeding we don't bother to adjust the entropy count, though,
         * because we're not ambitious to provide *information-theoretic*
         * randomness. NOTE: This approach fails if the program forks before
         * we have enough entropy. Entropy should be collected in a separate
         * input pool and be transferred to the output pool only when the
         * entropy limit has been reached.
         */
        entropy -= num;
        if (entropy < 0)
            entropy = 0;
    }

    if (do_stir_pool) {
        /*
         * In the output function only half of 'md' remains secret, so we
         * better make sure that the required entropy gets 'evenly
         * distributed' through 'state', our randomness pool. The input
         * function (rand_add) chains all of 'md', which makes it more
         * suitable for this purpose.
         */

        int n = STATE_SIZE;     /* so that the complete pool gets accessed */
        while (n > 0) {
#if MD_DIGEST_LENGTH > 20
# error "Please adjust DUMMY_SEED."
#endif
#define DUMMY_SEED "...................." /* at least MD_DIGEST_LENGTH */
            /*
             * Note that the seed does not matter, it's just that
             * rand_add expects to have something to hash.
             */
            rand_add(DUMMY_SEED, MD_DIGEST_LENGTH, 0.0);
            n -= MD_DIGEST_LENGTH;
        }
        if (ok)
            stirred_pool = 1;
    }

    st_idx = state_index;
    st_num = state_num;
    md_c[0] = md_count[0];
    md_c[1] = md_count[1];
    memcpy(local_md, md, sizeof md);

    state_index += num_ceil;
    if (state_index > state_num)
        state_index %= state_num;

    /*
     * state[st_idx], ..., state[(st_idx + num_ceil - 1) % st_num] are now
     * ours (but other threads may use them too)
     */

    md_count[0] += 1;

    /* before unlocking, we must clear 'crypto_lock_rand' */
    crypto_lock_rand = 0;
    ASYNC_unblock_pause();
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    while (num > 0) {
        /* num_ceil -= MD_DIGEST_LENGTH/2 */
        j = (num >= MD_DIGEST_LENGTH / 2) ? MD_DIGEST_LENGTH / 2 : num;
        num -= j;
        if (!MD_Init(&m))
            goto err;
#ifndef GETPID_IS_MEANINGLESS
        if (curr_pid) {         /* just in the first iteration to save time */
            if (!MD_Update(&m, (unsigned char *)&curr_pid, sizeof curr_pid))
                goto err;
            curr_pid = 0;
        }
#endif
        if (curr_time) {        /* just in the first iteration to save time */
            if (!MD_Update(&m, (unsigned char *)&curr_time, sizeof curr_time))
                goto err;
            if (!MD_Update(&m, (unsigned char *)&tv, sizeof tv))
                goto err;
            curr_time = 0;
            rand_hw_seed(&m);
        }
        if (!MD_Update(&m, local_md, MD_DIGEST_LENGTH))
            goto err;
        if (!MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c)))
            goto err;

#ifndef PURIFY                  /* purify complains */
        /*
         * The following line uses the supplied buffer as a small source of
         * entropy: since this buffer is often uninitialised it may cause
         * programs such as purify or valgrind to complain. So for those
         * builds it is not used: the removal of such a small source of
         * entropy has negligible impact on security.
         */
        if (!MD_Update(&m, buf, j))
            goto err;
#endif

        k = (st_idx + MD_DIGEST_LENGTH / 2) - st_num;
        if (k > 0) {
            if (!MD_Update(&m, &(state[st_idx]), MD_DIGEST_LENGTH / 2 - k))
                goto err;
            if (!MD_Update(&m, &(state[0]), k))
                goto err;
        } else if (!MD_Update(&m, &(state[st_idx]), MD_DIGEST_LENGTH / 2))
            goto err;
        if (!MD_Final(&m, local_md))
            goto err;

        for (i = 0; i < MD_DIGEST_LENGTH / 2; i++) {
            /* may compete with other threads */
            state[st_idx++] ^= local_md[i];
            if (st_idx >= st_num)
                st_idx = 0;
            if (i < j)
                *(buf++) = local_md[i + MD_DIGEST_LENGTH / 2];
        }
    }

    if (!MD_Init(&m)
        || !MD_Update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c))
        || !MD_Update(&m, local_md, MD_DIGEST_LENGTH))
        goto err;
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    /*
     * Prevent deadlocks if we end up in an async engine
     */
    ASYNC_block_pause();
    if (!MD_Update(&m, md, MD_DIGEST_LENGTH) || !MD_Final(&m, md)) {
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
        goto err;
    }
    ASYNC_unblock_pause();
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    EVP_MD_CTX_cleanup(&m);
    if (ok)
        return (1);
    else if (pseudo)
        return 0;
    else {
        RANDerr(RAND_F_RAND_BYTES, RAND_R_PRNG_NOT_SEEDED);
        ERR_add_error_data(1, "You need to read the OpenSSL FAQ, "
                           "http://www.openssl.org/support/faq.html");
        return (0);
    }
 err:
    EVP_MD_CTX_cleanup(&m);
    RANDerr(RAND_F_RAND_BYTES, ERR_R_EVP_LIB);
    return 0;

}

static int rand_nopseudo_bytes(unsigned char *buf, int num)
{
    return rand_bytes(buf, num, 0);
}

#ifndef OPENSSL_NO_DEPRECATED
/*
 * pseudo-random bytes that are guaranteed to be unique but not unpredictable
 */
static int rand_pseudo_bytes(unsigned char *buf, int num)
{
    return rand_bytes(buf, num, 1);
}
#endif

static int rand_status(void)
{
    CRYPTO_THREADID cur;
    int ret;
    int do_not_lock;

    CRYPTO_THREADID_current(&cur);
    /*
     * check if we already have the lock (could happen if a RAND_poll()
     * implementation calls RAND_status())
     */
    if (crypto_lock_rand) {
        CRYPTO_r_lock(CRYPTO_LOCK_RAND2);
        do_not_lock = !CRYPTO_THREADID_cmp(&locking_threadid, &cur);
        CRYPTO_r_unlock(CRYPTO_LOCK_RAND2);
    } else
        do_not_lock = 0;

    if (!do_not_lock) {
        CRYPTO_w_lock(CRYPTO_LOCK_RAND);
        /*
         * Prevent deadlocks in case we end up in an async engine
         */
        ASYNC_block_pause();

        /*
         * prevent rand_bytes() from trying to obtain the lock again
         */
        CRYPTO_w_lock(CRYPTO_LOCK_RAND2);
        CRYPTO_THREADID_cpy(&locking_threadid, &cur);
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND2);
        crypto_lock_rand = 1;
    }

    if (!initialized) {
        RAND_poll();
        initialized = 1;
    }

    ret = entropy >= ENTROPY_NEEDED;

    if (!do_not_lock) {
        /* before unlocking, we must clear 'crypto_lock_rand' */
        crypto_lock_rand = 0;

        ASYNC_unblock_pause();
        CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    }

    return ret;
}

/*
 * rand_hw_seed: get seed data from any available hardware RNG. only
 * currently supports rdrand.
 */

/* Adapted from eng_rdrand.c */

#if (defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined (_M_X64)) && defined(OPENSSL_CPUID_OBJ)

# define RDRAND_CALLS    4

size_t OPENSSL_ia32_rdrand(void);
extern unsigned int OPENSSL_ia32cap_P[];

static void rand_hw_seed(EVP_MD_CTX *ctx)
{
    int i;
    if (!(OPENSSL_ia32cap_P[1] & (1 << (62 - 32))))
        return;
    for (i = 0; i < RDRAND_CALLS; i++) {
        size_t rnd;
        rnd = OPENSSL_ia32_rdrand();
        if (rnd == 0)
            return;
        MD_Update(ctx, (unsigned char *)&rnd, sizeof(size_t));
    }
}

/* XOR an existing buffer with random data */

void rand_hw_xor(unsigned char *buf, size_t num)
{
    size_t rnd;
    if (!(OPENSSL_ia32cap_P[1] & (1 << (62 - 32))))
        return;
    while (num >= sizeof(size_t)) {
        rnd = OPENSSL_ia32_rdrand();
        if (rnd == 0)
            return;
        *((size_t *)buf) ^= rnd;
        buf += sizeof(size_t);
        num -= sizeof(size_t);
    }
    if (num) {
        rnd = OPENSSL_ia32_rdrand();
        if (rnd == 0)
            return;
        while (num) {
            *buf ^= rnd & 0xff;
            rnd >>= 8;
            buf++;
            num--;
        }
    }
}

#else

static void rand_hw_seed(EVP_MD_CTX *ctx)
{
    return;
}

void rand_hw_xor(unsigned char *buf, size_t num)
{
    return;
}

#endif
