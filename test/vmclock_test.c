/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The DRBGs' reseed on a change of the VMClock page. This program builds its
 * own copy of the reader with a regular file in the working directory in
 * place of the device, and links libcrypto statically, so that the DRBGs of
 * the default provider read that file. Bumping the generation counter in it
 * must reseed the public and private DRBGs, and the primary through them, on
 * their next generate call; leaving it alone must not. Each test runs in its
 * own library context and puts the counter back before it returns.
 */
#define OSSL_VMCLOCK_DEVICE "vmclock_test.page"
#include "../providers/implementations/rands/vmclock.c"

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include "internal/nelem.h"
#include "testutil.h"

#ifdef OSSL_VMCLOCK_SUPPORTED
#define VMCLOCK_TEST_SIZE 4096

static int vmclock_test_created;
static uint8_t *vmclock_test_page;
static uint32_t vmclock_test_seq = 2;
static uint64_t vmclock_test_generation;
static time_t vmclock_test_changed_at;

static int vmclock_test_setup(void)
{
    static const uint8_t header[32] = {
        'V', 'C', 'L', 'K', 112, 0, 0, 0, 1, 0, 1, 0, 2, 0, 0, 0, /* magic, size, version, ids, seq */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 /* marker, flags = GEN_COUNTER_PRESENT */
    };
    static uint8_t page[VMCLOCK_TEST_SIZE];
    int fd;

    memcpy(page, header, sizeof(header));
    fd = open(OSSL_VMCLOCK_DEVICE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return 0;
    vmclock_test_created = 1;
    if (write(fd, page, sizeof(page)) != (ssize_t)sizeof(page)) {
        close(fd);
        return 0;
    }
    vmclock_test_page = mmap(NULL, sizeof(page), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (vmclock_test_page == MAP_FAILED) {
        vmclock_test_page = NULL;
        return 0;
    }
    return 1;
}

/* Every field of the page is little-endian. */
static void vmclock_test_put(size_t off, uint64_t v, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        vmclock_test_page[off + i] = (uint8_t)(v >> (8 * i));
}

/* The readers load seq_count in one access, so it is stored in one. */
static void vmclock_test_set_seq(uint32_t seq)
{
    uint8_t b[4];
    uint32_t raw;
    int i;

    for (i = 0; i < 4; i++)
        b[i] = (uint8_t)(seq >> (8 * i));
    memcpy(&raw, b, sizeof(raw));
    __atomic_store_n((uint32_t *)(vmclock_test_page + 12), raw, __ATOMIC_SEQ_CST);
}

/*
 * A DRBG reseeds again a second or more after a change. A test that counts
 * the reseeds of calls that follow a change therefore counts them only while
 * the clock still shows the second in which the page changed, and takes the
 * count as given if a stalled machine brings it there later.
 */
static int vmclock_test_in_time(void)
{
    return time(NULL) == vmclock_test_changed_at;
}

/* Set the generation counter as a hypervisor does, holding the page odd for |hold_ms|. */
static void vmclock_test_set_generation(uint64_t generation, unsigned int hold_ms)
{
    vmclock_test_changed_at = time(NULL);
    vmclock_test_generation = generation;
    vmclock_test_set_seq(++vmclock_test_seq); /* odd: update in progress */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    vmclock_test_put(104, generation, 8);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (hold_ms > 0)
        OSSL_sleep(hold_ms);
    vmclock_test_set_seq(++vmclock_test_seq);
}

static void vmclock_test_bump(unsigned int hold_ms)
{
    vmclock_test_set_generation(vmclock_test_generation + 1, hold_ms);
}

static unsigned int vmclock_reseed_counter(EVP_RAND_CTX *drbg)
{
    unsigned int n = 0;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &n);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_get_params(drbg, params))
        return 0;
    return n;
}

static int test_rand_reseed_on_vmclock(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *primary, *public, *private;
    uint64_t generation = vmclock_test_generation;
    unsigned char buf[32];
    unsigned int pri, pub, pri2, pub2;
    int ret = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;
    if (!TEST_ptr(primary = RAND_get0_primary(ctx))
        || !TEST_ptr(public = RAND_get0_public(ctx))
        || !TEST_ptr(private = RAND_get0_private(ctx))
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_true(RAND_priv_bytes_ex(ctx, buf, sizeof(buf), 0)))
        goto err;
    pri = vmclock_reseed_counter(primary);
    pub = vmclock_reseed_counter(public);

    /* nothing changed: no reseed */
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri))
        goto err;

    /* the generation counter moved: the public DRBG reseeds, and the primary with it */
    vmclock_test_bump(0);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0)))
        goto err;
    pub2 = vmclock_reseed_counter(public);
    pri2 = vmclock_reseed_counter(primary);
    if (!TEST_uint_eq(pub2, pub + 1) || !TEST_uint_eq(pri2, pri + 1))
        goto err;
    /* and the private DRBG on its next call, once */
    if (!TEST_true(RAND_priv_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_true(RAND_priv_bytes_ex(ctx, buf, sizeof(buf), 0))
        || (vmclock_test_in_time()
            && !TEST_uint_eq(vmclock_reseed_counter(primary), pri2)))
        goto err;
    ret = 1;
err:
    vmclock_test_set_generation(generation, 0);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

/*
 * A seed source that moves the counter while a DRBG takes seed from it, that
 * is, after the DRBG's check before generating and before its check after.
 * It records the prediction resistance asked of each seed request.
 */
static int vmclock_seed_bumps, vmclock_seed_requests, vmclock_seed_pr[4];

static void *vmclock_seed_newctx(ossl_unused void *provctx,
    ossl_unused void *parent, ossl_unused const OSSL_DISPATCH *pd)
{
    int *state = OPENSSL_zalloc(sizeof(*state));

    if (state != NULL)
        *state = EVP_RAND_STATE_UNINITIALISED;
    return state;
}

static void vmclock_seed_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int vmclock_seed_instantiate(void *vctx, ossl_unused unsigned int strength,
    ossl_unused int prediction_resistance, ossl_unused const unsigned char *pstr,
    ossl_unused size_t pstr_len, ossl_unused const OSSL_PARAM params[])
{
    *(int *)vctx = EVP_RAND_STATE_READY;
    return 1;
}

static int vmclock_seed_uninstantiate(void *vctx)
{
    *(int *)vctx = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int vmclock_seed_generate(ossl_unused void *vctx, unsigned char *out,
    size_t outlen, ossl_unused unsigned int strength,
    ossl_unused int prediction_resistance, ossl_unused const unsigned char *adin,
    ossl_unused size_t adinlen)
{
    memset(out, 0x5a, outlen);
    return 1;
}

static size_t vmclock_seed_get_seed(ossl_unused void *vctx, unsigned char **pout,
    int entropy, size_t min_len, size_t max_len, int prediction_resistance,
    ossl_unused const unsigned char *adin, ossl_unused size_t adinlen)
{
    size_t len = entropy > 0 ? ((size_t)entropy + 7) / 8 : 0;

    if (len < min_len)
        len = min_len;
    if (len > max_len)
        len = max_len;
    if (len == 0 || (*pout = OPENSSL_malloc(len)) == NULL)
        return 0;
    memset(*pout, 0x5a + vmclock_seed_requests, len);
    if (vmclock_seed_requests < (int)OSSL_NELEM(vmclock_seed_pr))
        vmclock_seed_pr[vmclock_seed_requests] = prediction_resistance;
    vmclock_seed_requests++;
    if (vmclock_seed_bumps > 0) {
        vmclock_seed_bumps--;
        vmclock_test_bump(0);
    }
    return len;
}

static void vmclock_seed_clear_seed(ossl_unused void *vctx, unsigned char *out,
    size_t outlen)
{
    OPENSSL_clear_free(out, outlen);
}

static int vmclock_seed_enable_locking(ossl_unused void *vctx)
{
    return 1;
}

static int vmclock_seed_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, *(int *)vctx))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 256))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1 << 16))
        return 0;
    return 1;
}

static const OSSL_PARAM *vmclock_seed_gettable_ctx_params(ossl_unused void *vctx,
    ossl_unused void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    return known;
}

static const OSSL_DISPATCH vmclock_seed_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))vmclock_seed_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))vmclock_seed_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))vmclock_seed_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))vmclock_seed_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))vmclock_seed_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))vmclock_seed_enable_locking },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))vmclock_seed_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))vmclock_seed_get_ctx_params },
    { OSSL_FUNC_RAND_GET_SEED, (void (*)(void))vmclock_seed_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))vmclock_seed_clear_seed },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM vmclock_seed_rand[] = {
    { "VMCLOCK-SEED", "provider=vmclock-seed", vmclock_seed_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *vmclock_seed_query(ossl_unused void *provctx,
    int operation_id, int *no_cache)
{
    *no_cache = 0;
    return operation_id == OSSL_OP_RAND ? vmclock_seed_rand : NULL;
}

static const OSSL_DISPATCH vmclock_seed_method[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))vmclock_seed_query },
    OSSL_DISPATCH_END
};

static int vmclock_seed_provider_init(ossl_unused const OSSL_CORE_HANDLE *handle,
    ossl_unused const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
    void **provctx)
{
    *provctx = NULL;
    *out = vmclock_seed_method;
    return 1;
}

/*
 * The counter moves before a call, which the check before generating sees,
 * and again while the DRBG reseeds for that call, which only the check after
 * generating can see: the DRBG must reseed a second time, with the prediction
 * resistance the caller asked for, and then be settled.
 */
static int test_rand_vmclock_recheck(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *dflt = NULL, *seed = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *parent = NULL, *drbg = NULL;
    OSSL_PARAM params[2];
    uint64_t generation = vmclock_test_generation;
    unsigned char buf[32];
    unsigned int n;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
        (char *)"AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(dflt = OSSL_PROVIDER_load(ctx, "default"))
        || !TEST_true(OSSL_PROVIDER_add_builtin(ctx, "vmclock-seed",
            vmclock_seed_provider_init))
        || !TEST_ptr(seed = OSSL_PROVIDER_load(ctx, "vmclock-seed"))
        || !TEST_ptr(rand = EVP_RAND_fetch(ctx, "VMCLOCK-SEED", NULL))
        || !TEST_ptr(parent = EVP_RAND_CTX_new(rand, NULL))
        || !TEST_true(EVP_RAND_instantiate(parent, 0, 0, NULL, 0, NULL)))
        goto err;
    EVP_RAND_free(rand);
    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "CTR-DRBG", NULL))
        || !TEST_ptr(drbg = EVP_RAND_CTX_new(rand, parent))
        || !TEST_true(EVP_RAND_instantiate(drbg, 256, 0, NULL, 0, params))
        || !TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 0, NULL, 0)))
        goto err;
    n = vmclock_reseed_counter(drbg);

    vmclock_seed_requests = 0;
    vmclock_seed_bumps = 1;
    vmclock_test_bump(0);
    if (!TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 1, NULL, 0))
        || !TEST_uint_eq(vmclock_reseed_counter(drbg), n + 2)
        || !TEST_int_eq(vmclock_seed_requests, 2)
        || !TEST_int_eq(vmclock_seed_pr[0], 1)
        || !TEST_int_eq(vmclock_seed_pr[1], 1))
        goto err;

    n = vmclock_reseed_counter(drbg);
    if (!TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 0, NULL, 0))
        || !TEST_uint_eq(vmclock_reseed_counter(drbg), n))
        goto err;
    ret = 1;
err:
    vmclock_seed_bumps = 0;
    vmclock_test_set_generation(generation, 0);
    EVP_RAND_CTX_free(drbg);
    EVP_RAND_CTX_free(parent);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(seed);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

/*
 * A page left odd, as if the hypervisor stopped in the middle of an update:
 * the read gives up after a bounded number of looks, the call succeeds and
 * the DRBGs reseed once. While the page stays odd they do not reseed again,
 * and when it is consistent again they reseed once more, whether or not the
 * counter moved meanwhile.
 */
static int test_rand_vmclock_stuck(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *primary, *public;
    unsigned char buf[32];
    unsigned int pri, pub;
    int ret = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_ptr(public = RAND_get0_public(ctx))
        || !TEST_ptr(primary = RAND_get0_primary(ctx)))
        goto err;
    pub = vmclock_reseed_counter(public);
    pri = vmclock_reseed_counter(primary);

    /*
     * The first read that gives up counts as a change: the public DRBG
     * reseeds, and the primary with it, once each.
     */
    vmclock_test_set_seq(++vmclock_test_seq);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 1)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1))
        goto err;
    /* the page stays odd: no further reseed */
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 1)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1))
        goto err;
    /* it settles, the counter where it was: one more reseed, then none */
    vmclock_test_changed_at = time(NULL);
    vmclock_test_set_seq(++vmclock_test_seq);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 2)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 2)
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || (vmclock_test_in_time()
            && (!TEST_uint_eq(vmclock_reseed_counter(public), pub + 2)
                || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 2))))
        goto err;
    ret = 1;
err:
    if ((vmclock_test_seq & 1) != 0)
        vmclock_test_set_seq(++vmclock_test_seq);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

/*
 * After a change a DRBG reseeds again on its first call once a wait is over,
 * and the primary with it, so that seed taken before the guest's kernel had
 * reseeded does not stay. This runs through the first wait; the second is
 * too long for a test and takes the same path.
 */
static int test_rand_vmclock_followup(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *primary, *public;
    uint64_t generation = vmclock_test_generation;
    unsigned char buf[32];
    unsigned int pri, pub;
    int ret = 0;

    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new()))
        return 0;
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_ptr(public = RAND_get0_public(ctx))
        || !TEST_ptr(primary = RAND_get0_primary(ctx)))
        goto err;
    pub = vmclock_reseed_counter(public);
    pri = vmclock_reseed_counter(primary);

    /* the change itself: one reseed each, and none on the next call */
    vmclock_test_bump(0);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 1)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1)
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || (vmclock_test_in_time()
            && (!TEST_uint_eq(vmclock_reseed_counter(public), pub + 1)
                || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1))))
        goto err;
    /* the first wait is over: one more reseed each, and none after it */
    OSSL_sleep(1100);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 2)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 2)
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 2)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 2))
        goto err;
    ret = 1;
err:
    vmclock_test_set_generation(generation, 0);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

#if defined(OPENSSL_THREADS)
#include <pthread.h>

/*
 * Threads draw from their public and private DRBGs, and so from the shared
 * primary, while the counter moves under them, now and then with the page
 * held odd. This checks that the calls succeed and end in a settled state; it
 * cannot force any particular interleaving. Afterwards one more bump must
 * reseed the primary exactly once and every thread's public DRBG on its next
 * call, and once all have seen it, a further call must not reseed.
 */
#define VMCLOCK_THREADS 4
#define VMCLOCK_BUMPS 2000

static int vmclock_stop, vmclock_phases;
static pthread_barrier_t vmclock_barrier;
static OSSL_LIB_CTX *vmclock_ctx;

static void *vmclock_thread(void *arg)
{
    int *ok = arg;
    unsigned char buf[32];
    EVP_RAND_CTX *public;
    unsigned int before;

    *ok = 1;
    while (!__atomic_load_n(&vmclock_stop, __ATOMIC_ACQUIRE))
        if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
            || !RAND_priv_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0))
            *ok = 0;
    if (!vmclock_phases)
        goto end;
    if ((public = RAND_get0_public(vmclock_ctx)) == NULL)
        *ok = 0;
    before = public == NULL ? 0 : vmclock_reseed_counter(public);
    pthread_barrier_wait(&vmclock_barrier); /* the main thread bumps */
    pthread_barrier_wait(&vmclock_barrier);
    if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
        || public == NULL || vmclock_reseed_counter(public) == before)
        *ok = 0;
    pthread_barrier_wait(&vmclock_barrier); /* every thread has drawn once */
    before = public == NULL ? 0 : vmclock_reseed_counter(public);
    if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
        || public == NULL
        || (vmclock_test_in_time() && vmclock_reseed_counter(public) != before))
        *ok = 0;
end:
    OPENSSL_thread_stop();
    return NULL;
}

static int test_rand_vmclock_threads(void)
{
    pthread_t t[VMCLOCK_THREADS];
    int ok[VMCLOCK_THREADS];
    EVP_RAND_CTX *primary = NULL;
    uint64_t generation = vmclock_test_generation;
    unsigned int pri = 0;
    int i, n, ret = 1;

    if (!TEST_ptr(vmclock_ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(primary = RAND_get0_primary(vmclock_ctx))) {
        OSSL_LIB_CTX_free(vmclock_ctx);
        vmclock_ctx = NULL;
        return 0;
    }
    for (n = 0; n < VMCLOCK_THREADS; n++)
        if (pthread_create(&t[n], NULL, vmclock_thread, &ok[n]) != 0)
            break;
    /* the threads look at vmclock_phases only after vmclock_stop is set */
    vmclock_phases = TEST_int_eq(n, VMCLOCK_THREADS)
        && TEST_int_eq(pthread_barrier_init(&vmclock_barrier, NULL, n + 1), 0);
    for (i = 0; i < VMCLOCK_BUMPS; i++) {
        vmclock_test_bump(i % 100 == 0 ? 1 : 0);
        if (i % 20 == 19)
            OSSL_sleep(1);
    }
    __atomic_store_n(&vmclock_stop, 1, __ATOMIC_RELEASE);
    if (vmclock_phases) {
        pthread_barrier_wait(&vmclock_barrier);
        pri = vmclock_reseed_counter(primary);
        vmclock_test_bump(0);
        pthread_barrier_wait(&vmclock_barrier);
        pthread_barrier_wait(&vmclock_barrier);
    }
    for (i = 0; i < n; i++) {
        pthread_join(t[i], NULL);
        if (!TEST_true(ok[i]))
            ret = 0;
    }
    if (vmclock_phases) {
        pthread_barrier_destroy(&vmclock_barrier);
        if (vmclock_test_in_time()
            && !TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1))
            ret = 0;
    }
    vmclock_test_set_generation(generation, 0);
    OSSL_LIB_CTX_free(vmclock_ctx);
    vmclock_ctx = NULL;
    return vmclock_phases && ret;
}
#endif
#endif

int setup_tests(void)
{
#ifdef OSSL_VMCLOCK_SUPPORTED
    if (!vmclock_test_setup()) {
        TEST_note("no file to stand in for the VMClock page; its tests are skipped");
        return 1;
    }
    ADD_TEST(test_rand_reseed_on_vmclock);
    ADD_TEST(test_rand_vmclock_recheck);
    ADD_TEST(test_rand_vmclock_stuck);
    ADD_TEST(test_rand_vmclock_followup);
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_rand_vmclock_threads);
#endif
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifdef OSSL_VMCLOCK_SUPPORTED
    if (vmclock_test_page != NULL)
        munmap(vmclock_test_page, VMCLOCK_TEST_SIZE);
    if (vmclock_test_created)
        unlink(OSSL_VMCLOCK_DEVICE);
#endif
}
