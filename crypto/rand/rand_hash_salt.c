/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include "crypto/rand.h"
#include "crypto/siphash.h"
#include "internal/cryptlib.h"
#include "internal/time.h"
#include "internal/tsan_assist.h"

/*
 * Last resort: condense the current time, the time stamp counter (where the
 * CPU has one), the process (fork) and thread ids, a call counter and a
 * couple of addresses (ASLR) into |num| bytes with SipHash-2-4. Within a
 * process the counter makes the result differ on every call, and the process
 * id and time keep forked children apart.
 *
 * This is not entropy in the cryptographic sense. With a time stamp counter
 * or address space randomisation it is not practically guessable by a
 * remote peer, which is all a hash-flooding defense needs. On a platform
 * with neither, it only rests on the clock, the process and thread ids and
 * the call count, which a peer may be able to narrow down; nothing better is
 * left once RAND and the operating system sources have failed.
 */
static int hash_salt_fallback(unsigned char *buf, size_t num)
{
    static TSAN_QUALIFIER unsigned int counter;
    static const unsigned char zero_key[SIPHASH_KEY_SIZE] = { 0 };
    struct {
        OSSL_TIME now;
        uint32_t tsc;
        unsigned int counter;
        int pid;
        CRYPTO_THREAD_ID tid;
        const void *stack;
        const void *data;
    } salt;
    unsigned char block[SIPHASH_MAX_DIGEST_SIZE];
    size_t off, n;
    uint64_t i;
    SIPHASH sip;
    int ret = 0;

    memset(&salt, 0, sizeof(salt));
    salt.now = ossl_time_now();
    salt.tsc = OPENSSL_rdtsc();
    salt.counter = tsan_counter(&counter);
    salt.pid = openssl_get_fork_id();
    salt.tid = CRYPTO_THREAD_get_current_id();
    salt.stack = &salt;
    salt.data = &zero_key;

    for (i = 0, off = 0; off < num; i++, off += n) {
        memset(&sip, 0, sizeof(sip));
        if (!SipHash_set_hash_size(&sip, SIPHASH_MAX_DIGEST_SIZE)
            || !SipHash_Init(&sip, zero_key, 0, 0))
            goto err;
        SipHash_Update(&sip, (unsigned char *)&i, sizeof(i));
        SipHash_Update(&sip, (unsigned char *)&salt, sizeof(salt));
        if (!SipHash_Final(&sip, block, sizeof(block)))
            goto err;
        n = num - off < sizeof(block) ? num - off : sizeof(block);
        memcpy(buf + off, block, n);
    }
    ret = 1;
err:
    OPENSSL_cleanse(block, sizeof(block));
    return ret;
}

/*
 * Fill |buf| with a |num| byte salt for hashing untrusted input, e.g. the
 * SipHash key of a hash table indexed by attacker controlled data, so that
 * colliding inputs cannot be precomputed (hash flooding). The salt only has
 * to be unpredictable, not secret: never use this for cryptographic keys,
 * IVs, nonces or anything else that must come from a CSPRNG.
 *
 * Such tables must keep working in library contexts that have no usable
 * RAND, e.g. when only the null provider is loaded, so this tries in turn:
 *
 *  1. RAND_bytes_ex() on |ctx|,
 *  2. the operating system entropy sources, unless |ctx| has a strict seed
 *     source configuration, which they must not stand in for,
 *  3. time, time stamp counter, process and thread ids and addresses, see
 *     hash_salt_fallback(). This is used with strict seeding as well: it
 *     makes a hash salt, not seed material.
 *
 * Errors raised by a source that failed are discarded when a later one
 * succeeds. Returns 1 on success and 0 if every source failed.
 */
int ossl_rand_hash_salt(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num)
{
    unsigned char *seed = NULL;
    size_t seed_len;
    int ok;

    if (num == 0)
        return 1;

    ERR_set_mark();
    if (RAND_bytes_ex(ctx, buf, num, 0) > 0)
        goto done;

    /*
     * Read the operating system sources directly rather than through
     * ossl_rand_get_user_entropy(), which would consult, and with strict
     * seeding create, the seed source of |ctx| from within the caller (e.g.
     * certificate parsing), and whose cleanup cannot reliably tell which of
     * the two allocated a buffer. ossl_rand_get_entropy() and
     * ossl_rand_cleanup_entropy() always pair up.
     */
    if (num <= RAND_POOL_MAX_LENGTH && !ossl_rand_seed_source_strict(ctx)) {
        seed_len = ossl_rand_get_entropy(ctx, &seed, (int)(8 * num), num, num);
        ok = seed_len == num;
        if (ok)
            memcpy(buf, seed, num);
        ossl_rand_cleanup_entropy(ctx, seed, seed_len);
        if (ok)
            goto done;
    }

    if (hash_salt_fallback(buf, num))
        goto done;

    ERR_clear_last_mark();
    ERR_raise(ERR_LIB_RAND, RAND_R_ERROR_RETRIEVING_ENTROPY);
    return 0;

done:
    ERR_pop_to_mark();
    return 1;
}
