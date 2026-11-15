/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Times the two users of the library's internal hash table: the namemap
 * (name -> number, read without a lock on every fetch by name) and the
 * X509_STORE (name -> objects, under the store's lock). It only uses
 * interfaces that do not depend on how either is implemented, so the same
 * source measures any two versions of the library against each other.
 *
 * Not run by "make test". Each line of output is "<case> <value> <unit>",
 * the best of a few repetitions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "internal/namemap.h"
#include "internal/nelem.h"
#include "internal/time.h"
#include "threadstest.h"

#define REPEATS 7
#define MAX_THREADS 8

static uint64_t now_ns(void)
{
    return ossl_time2ticks(ossl_time_now()) / (OSSL_TIME_SECOND / 1000000000);
}

static void report(const char *name, double value, const char *unit)
{
    printf("%-34s %12.2f %s\n", name, value, unit);
    fflush(stdout);
}

static void die(const char *what)
{
    fprintf(stderr, "FAILED: %s\n", what);
    exit(1);
}

/* A cheap deterministic sequence, so every run visits keys the same way. */
static uint32_t next_rand(uint32_t *state)
{
    *state = *state * 1664525u + 1013904223u;
    return *state >> 8;
}

/*-
 * Namemap
 * =======
 */

static char **nm_names;
static size_t nm_num_names, nm_cap_names;
static OSSL_NAMEMAP *nm_shared;
static int nm_sink;

static void nm_collect(const char *name, void *arg)
{
    if (nm_num_names == nm_cap_names) {
        nm_cap_names = nm_cap_names == 0 ? 1024 : nm_cap_names * 2;
        nm_names = realloc(nm_names, nm_cap_names * sizeof(*nm_names));
        if (nm_names == NULL)
            die("realloc");
    }
    if ((nm_names[nm_num_names++] = strdup(name)) == NULL)
        die("strdup");
}

static void md_cb(EVP_MD *m, void *arg)
{
}

static void cipher_cb(EVP_CIPHER *c, void *arg)
{
}

static void mac_cb(EVP_MAC *m, void *arg)
{
}

static void kdf_cb(EVP_KDF *k, void *arg)
{
}

static void keymgmt_cb(EVP_KEYMGMT *k, void *arg)
{
}

static void sig_cb(EVP_SIGNATURE *s, void *arg)
{
}

static void kem_cb(EVP_KEM *k, void *arg)
{
}

static void kex_cb(EVP_KEYEXCH *k, void *arg)
{
}

static void rand_cb(EVP_RAND *r, void *arg)
{
}

/* Every name the default library context knows once it is fully loaded. */
static void nm_load_real_names(void)
{
    int number;

    EVP_MD_do_all_provided(NULL, md_cb, NULL);
    EVP_CIPHER_do_all_provided(NULL, cipher_cb, NULL);
    EVP_MAC_do_all_provided(NULL, mac_cb, NULL);
    EVP_KDF_do_all_provided(NULL, kdf_cb, NULL);
    EVP_KEYMGMT_do_all_provided(NULL, keymgmt_cb, NULL);
    EVP_SIGNATURE_do_all_provided(NULL, sig_cb, NULL);
    EVP_KEM_do_all_provided(NULL, kem_cb, NULL);
    EVP_KEYEXCH_do_all_provided(NULL, kex_cb, NULL);
    EVP_RAND_do_all_provided(NULL, rand_cb, NULL);

    nm_shared = ossl_namemap_stored(NULL);
    if (nm_shared == NULL)
        die("ossl_namemap_stored");
    for (number = 1; ossl_namemap_doall_names(nm_shared, number, nm_collect,
             NULL);
        number++)
        continue;
    if (nm_num_names == 0)
        die("no names");
}

#define NM_LOOKUPS 2000000

/* ns per lookup of names that exist, visited in a scattered order */
static double nm_time_hits(void)
{
    uint32_t seed = 12345;
    uint64_t start;
    int i, sum = 0;

    start = now_ns();
    for (i = 0; i < NM_LOOKUPS; i++)
        sum += ossl_namemap_name2num(nm_shared,
            nm_names[next_rand(&seed) % nm_num_names]);
    start = now_ns() - start;
    if (sum == 0)
        die("namemap hits");
    nm_sink += sum;
    return (double)start / NM_LOOKUPS;
}

static double nm_time_one_hot(void)
{
    uint64_t start;
    int i, sum = 0;

    start = now_ns();
    for (i = 0; i < NM_LOOKUPS; i++)
        sum += ossl_namemap_name2num(nm_shared, "SHA2-256");
    start = now_ns() - start;
    if (sum == 0)
        die("namemap SHA2-256");
    nm_sink += sum;
    return (double)start / NM_LOOKUPS;
}

static double nm_time_misses(void)
{
    static const char *const absent[] = {
        "no-such-algorithm", "SHA2-257", "AES-512-GCM", "x", "RSA-PSS-PSS",
        "ML-KEM-2048", "id-absent-name-with-a-rather-long-tail-0123456789",
        "CHACHA21"
    };
    uint64_t start;
    int i, sum = 0;

    start = now_ns();
    for (i = 0; i < NM_LOOKUPS; i++)
        sum += ossl_namemap_name2num(nm_shared, absent[i & 7]);
    start = now_ns() - start;
    if (sum != 0)
        die("namemap misses");
    return (double)start / NM_LOOKUPS;
}

static double nm_time_fetch(void)
{
    uint64_t start;
    int i;
    const int n = 500000;

    start = now_ns();
    for (i = 0; i < n; i++) {
        EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);

        if (md == NULL)
            die("EVP_MD_fetch");
        EVP_MD_free(md);
    }
    return (double)(now_ns() - start) / n;
}

/* Readers on all threads at once: total lookups per second, in millions. */
static CRYPTO_RWLOCK *mt_lock;
static int mt_go, mt_ready;

static void mt_wait_for_start(void)
{
    int go = 0, dummy;

    (void)CRYPTO_atomic_add(&mt_ready, 1, &dummy, mt_lock);
    while (!go)
        if (!CRYPTO_atomic_load_int(&mt_go, &go, mt_lock))
            die("atomic load");
}

static uint64_t mt_run(int nthreads, void (*fn)(void))
{
    thread_t t[MAX_THREADS];
    int i, ready = 0;
    uint64_t start;

    mt_go = 0;
    mt_ready = 0;
    for (i = 0; i < nthreads; i++)
        if (!run_thread(&t[i], fn))
            die("run_thread");
    while (ready < nthreads)
        if (!CRYPTO_atomic_load_int(&mt_ready, &ready, mt_lock))
            die("atomic load");
    start = now_ns();
    if (!CRYPTO_atomic_store_int(&mt_go, 1, mt_lock))
        die("atomic store");
    for (i = 0; i < nthreads; i++)
        if (!wait_for_thread(t[i]))
            die("wait_for_thread");
    return now_ns() - start;
}

static void nm_reader(void)
{
    uint32_t seed = (uint32_t)(uintptr_t)&seed;
    int i, sum = 0;

    mt_wait_for_start();
    for (i = 0; i < NM_LOOKUPS; i++)
        sum += ossl_namemap_name2num(nm_shared,
            nm_names[next_rand(&seed) % nm_num_names]);
    if (sum == 0)
        die("namemap mt hits");
}

/* us to register |count| new names (and as many aliases) in a new namemap */
static double nm_time_add(int count, int *failed)
{
    OSSL_NAMEMAP *nm = ossl_namemap_new(NULL);
    char name[48];
    uint64_t start;
    int i, num;

    if (nm == NULL)
        die("ossl_namemap_new");
    *failed = 0;
    start = now_ns();
    for (i = 0; i < count; i++) {
        snprintf(name, sizeof(name), "Algorithm-Name-%d", i);
        if ((num = ossl_namemap_add_name(nm, 0, name)) == 0) {
            *failed = i + 1;
            break;
        }
        snprintf(name, sizeof(name), "1.3.6.1.4.1.99999.%d", i);
        if (ossl_namemap_add_name(nm, num, name) != num) {
            *failed = i + 1;
            break;
        }
    }
    start = now_ns() - start;
    ossl_namemap_free(nm);
    return (double)start / 1000;
}

/* ns per lookup in a namemap holding |count| names and as many aliases */
static double nm_time_sized_hits(int count)
{
    OSSL_NAMEMAP *nm = ossl_namemap_new(NULL);
    char (*names)[48] = malloc((size_t)count * sizeof(*names));
    uint32_t seed = 777;
    uint64_t start;
    int i, num, sum = 0;

    if (nm == NULL || names == NULL)
        die("sized namemap");
    for (i = 0; i < count; i++) {
        snprintf(names[i], sizeof(names[i]), "Algorithm-Name-%d", i);
        if ((num = ossl_namemap_add_name(nm, 0, names[i])) == 0)
            die("sized namemap add");
        snprintf(names[i], sizeof(names[i]), "1.3.6.1.4.1.99999.%d", i);
        if (ossl_namemap_add_name(nm, num, names[i]) != num)
            die("sized namemap alias");
    }
    start = now_ns();
    for (i = 0; i < NM_LOOKUPS; i++)
        sum += ossl_namemap_name2num(nm, names[next_rand(&seed) % count]);
    start = now_ns() - start;
    if (sum == 0)
        die("sized namemap hits");
    nm_sink += sum;
    free(names);
    ossl_namemap_free(nm);
    return (double)start / NM_LOOKUPS;
}

/*-
 * X509_STORE
 * ==========
 */

static X509 **xs_certs;
static X509_NAME **xs_absent;
static int xs_num_certs;
#define XS_ABSENT 64
#define XS_SAME_NAME 4

static X509_NAME *xs_make_name(const char *cn_prefix, int i)
{
    X509_NAME *nm = X509_NAME_new();
    char cn[64];

    snprintf(cn, sizeof(cn), "%s %d", cn_prefix, i);
    if (nm == NULL
        || !X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC,
            (const unsigned char *)"CZ", -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC,
            (const unsigned char *)"Timing Trust Services", -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0))
        die("X509_NAME");
    return nm;
}

/*
 * |n| unsigned certificates. Every XS_SAME_NAME'th one shares its subject
 * with its predecessor, as cross-signed and re-issued CA certificates do.
 */
static void xs_make_certs(int n)
{
    int i;

    xs_certs = calloc(n, sizeof(*xs_certs));
    xs_absent = calloc(XS_ABSENT, sizeof(*xs_absent));
    if (xs_certs == NULL || xs_absent == NULL)
        die("calloc");
    for (i = 0; i < n; i++) {
        X509 *x = X509_new();
        X509_NAME *nm = xs_make_name("Timing Root CA",
            i % XS_SAME_NAME == XS_SAME_NAME - 1 ? i - 1 : i);

        if (x == NULL
            || !X509_set_subject_name(x, nm)
            || !X509_set_issuer_name(x, nm)
            || !ASN1_INTEGER_set(X509_get_serialNumber(x), i + 1))
            die("X509");
        X509_NAME_free(nm);
        xs_certs[i] = x;
    }
    for (i = 0; i < XS_ABSENT; i++)
        xs_absent[i] = xs_make_name("Unknown Issuing CA", i);
    xs_num_certs = n;
}

static void xs_free_certs(void)
{
    int i;

    for (i = 0; i < xs_num_certs; i++)
        X509_free(xs_certs[i]);
    for (i = 0; i < XS_ABSENT; i++)
        X509_NAME_free(xs_absent[i]);
    free(xs_certs);
    free(xs_absent);
}

static X509_STORE *xs_fill(int n)
{
    X509_STORE *store = X509_STORE_new();
    int i;

    if (store == NULL)
        die("X509_STORE_new");
    for (i = 0; i < n; i++)
        if (!X509_STORE_add_cert(store, xs_certs[i]))
            die("X509_STORE_add_cert");
    return store;
}

/* ns per certificate added to a new store, including freeing the store */
static double xs_time_add(int n)
{
    uint64_t start = now_ns();
    X509_STORE *store = xs_fill(n);

    X509_STORE_free(store);
    return (double)(now_ns() - start) / n;
}

static double xs_time_new_free(void)
{
    uint64_t start = now_ns();
    int i;
    const int n = 200000;

    for (i = 0; i < n; i++) {
        X509_STORE *store = X509_STORE_new();

        if (store == NULL)
            die("X509_STORE_new");
        X509_STORE_free(store);
    }
    return (double)(now_ns() - start) / n;
}

static X509_STORE *xs_shared;
static int xs_shared_n;
#define XS_LOOKUPS 1000000

static void xs_lookups(int hits, uint32_t seed)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_OBJECT *obj = X509_OBJECT_new();
    int i, found = 0;

    if (ctx == NULL || obj == NULL
        || !X509_STORE_CTX_init(ctx, xs_shared, NULL, NULL))
        die("X509_STORE_CTX");
    for (i = 0; i < XS_LOOKUPS; i++) {
        const X509_NAME *nm = hits
            ? X509_get_subject_name(xs_certs[next_rand(&seed) % xs_shared_n])
            : xs_absent[next_rand(&seed) % XS_ABSENT];

        if (X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, nm, obj)) {
            found++;
            /* |obj| is reused: drop the reference the lookup took */
            X509_free(X509_OBJECT_get0_X509(obj));
        }
    }
    if (found != (hits ? XS_LOOKUPS : 0))
        die("X509_STORE lookups");
    /* The references are gone already; free the shell only */
    OPENSSL_free(obj);
    X509_STORE_CTX_free(ctx);
}

static double xs_time_lookups(int hits)
{
    uint64_t start = now_ns();

    xs_lookups(hits, 4242);
    return (double)(now_ns() - start) / XS_LOOKUPS;
}

static void xs_reader(void)
{
    uint32_t seed = (uint32_t)(uintptr_t)&seed;

    mt_wait_for_start();
    xs_lookups(1, seed);
}

/* ns per name for collecting all the certificates of one subject */
static double xs_time_get1_certs(void)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    uint32_t seed = 99;
    uint64_t start;
    int i;
    const int n = 300000;

    if (ctx == NULL || !X509_STORE_CTX_init(ctx, xs_shared, NULL, NULL))
        die("X509_STORE_CTX");
    start = now_ns();
    for (i = 0; i < n; i++) {
        STACK_OF(X509) *sk = X509_STORE_CTX_get1_certs(ctx,
            X509_get_subject_name(xs_certs[next_rand(&seed) % xs_shared_n]));

        if (sk_X509_num(sk) < 1)
            die("X509_STORE_CTX_get1_certs");
        OSSL_STACK_OF_X509_free(sk);
    }
    start = now_ns() - start;
    X509_STORE_CTX_free(ctx);
    return (double)start / n;
}

/* ns per certificate for listing the whole store */
static double xs_time_all_certs(void)
{
    uint64_t start = now_ns();
    int i, reps = 1 + 200000 / xs_shared_n;

    for (i = 0; i < reps; i++) {
        STACK_OF(X509) *sk = X509_STORE_get1_all_certs(xs_shared);

        if (sk_X509_num(sk) != xs_shared_n)
            die("X509_STORE_get1_all_certs");
        OSSL_STACK_OF_X509_free(sk);
    }
    return (double)(now_ns() - start) / ((double)reps * xs_shared_n);
}

/*-
 * Driver
 * ======
 */

static double best(double (*fn)(void))
{
    double v, b = fn();
    int i;

    for (i = 1; i < REPEATS; i++)
        if ((v = fn()) < b)
            b = v;
    return b;
}

static int cur_arg;
static double call_xs_add(void)
{
    return xs_time_add(cur_arg);
}

static double call_xs_hits(void)
{
    return xs_time_lookups(1);
}

static double call_xs_misses(void)
{
    return xs_time_lookups(0);
}

static double call_nm_sized(void)
{
    return nm_time_sized_hits(cur_arg);
}

int main(void)
{
    static const int threads[] = { 1, 2, 4, 8 };
    static const int nm_sizes[] = { 250, 900 };
    static const int nm_add_sizes[] = { 250, 900, 5000 };
    static const int xs_sizes[] = { 150, 2000, 50000 };
    char label[64];
    size_t i, j;
    double v, b;
    int failed;

    if ((mt_lock = CRYPTO_THREAD_lock_new()) == NULL)
        die("lock");

    nm_load_real_names();
    report("namemap.names", (double)nm_num_names, "names");
    report("namemap.hit", best(nm_time_hits), "ns/lookup");
    report("namemap.hit.sha2-256", best(nm_time_one_hot), "ns/lookup");
    report("namemap.miss", best(nm_time_misses), "ns/lookup");
    report("evp_md_fetch.sha2-256", best(nm_time_fetch), "ns/fetch");
    for (i = 0; i < OSSL_NELEM(threads); i++) {
        b = 0;
        for (j = 0; j < REPEATS; j++) {
            v = (double)threads[i] * NM_LOOKUPS * 1000.0
                / (double)mt_run(threads[i], nm_reader);
            if (v > b)
                b = v;
        }
        snprintf(label, sizeof(label), "namemap.hit.threads=%d", threads[i]);
        report(label, b, "Mlookups/s");
    }
    for (i = 0; i < OSSL_NELEM(nm_sizes); i++) {
        cur_arg = nm_sizes[i];
        snprintf(label, sizeof(label), "namemap.hit.names=%d", 2 * cur_arg);
        report(label, best(call_nm_sized), "ns/lookup");
    }
    for (i = 0; i < OSSL_NELEM(nm_add_sizes); i++) {
        b = -1;
        for (failed = 0, j = 0; j < REPEATS; j++) {
            v = nm_time_add(nm_add_sizes[i], &failed);
            if (failed)
                break;
            if (b < 0 || v < b)
                b = v;
        }
        snprintf(label, sizeof(label), "namemap.add.names=%d",
            2 * nm_add_sizes[i]);
        if (failed)
            printf("%-34s %12s (failed at name pair %d)\n", label, "n/a",
                failed);
        else
            report(label, b * 1000 / (2 * nm_add_sizes[i]), "ns/name");
    }

    report("x509_store.new+free", best(xs_time_new_free), "ns");
    xs_make_certs(xs_sizes[OSSL_NELEM(xs_sizes) - 1]);
    for (i = 0; i < OSSL_NELEM(xs_sizes); i++) {
        cur_arg = xs_shared_n = xs_sizes[i];
        snprintf(label, sizeof(label), "x509_store.add.certs=%d", cur_arg);
        report(label, best(call_xs_add), "ns/cert");

        xs_shared = xs_fill(xs_shared_n);
        snprintf(label, sizeof(label), "x509_store.hit.certs=%d", cur_arg);
        report(label, best(call_xs_hits), "ns/lookup");
        snprintf(label, sizeof(label), "x509_store.miss.certs=%d", cur_arg);
        report(label, best(call_xs_misses), "ns/lookup");
        snprintf(label, sizeof(label), "x509_store.get1_certs.certs=%d",
            cur_arg);
        report(label, best(xs_time_get1_certs), "ns/name");
        snprintf(label, sizeof(label), "x509_store.all_certs.certs=%d",
            cur_arg);
        report(label, best(xs_time_all_certs), "ns/cert");
        if (i == 1) {
            for (j = 0; j < OSSL_NELEM(threads); j += 2) {
                int r;

                b = 0;
                for (r = 0; r < 3; r++) {
                    v = (double)threads[j] * XS_LOOKUPS * 1000.0
                        / (double)mt_run(threads[j], xs_reader);
                    if (v > b)
                        b = v;
                }
                snprintf(label, sizeof(label),
                    "x509_store.hit.certs=%d.threads=%d", cur_arg,
                    threads[j]);
                report(label, b, "Mlookups/s");
            }
        }
        X509_STORE_free(xs_shared);
    }
    xs_free_certs();

    for (i = 0; i < nm_num_names; i++)
        free(nm_names[i]);
    free(nm_names);
    CRYPTO_THREAD_lock_free(mt_lock);
    return nm_sink == 0;
}
