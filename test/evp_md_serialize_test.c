/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Cross-process EVP_MD_CTX serialization test.
 *
 * The serialized digest state must be independent of the implementation that
 * produced it (e.g. s390x CPACF vs. the generic software code). Platform
 * specific optimizations are selected at process start (e.g. via
 * OPENSSL_s390xcap), so the state is written to files by one process
 * ("write" mode) and read back and completed by another one ("read" mode),
 * which may run with a different set of optimizations enabled.
 *
 * Usage: evp_md_serialize_test write|read <file-prefix>
 *        evp_md_serialize_test reuse
 *
 * The "reuse" mode checks in a single process that a context, which was used
 * and finalized before, gives the same digest as a new one after it has been
 * initialized again.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "testutil.h"
#include "internal/nelem.h"

static const char *algs[] = {
    "SHA224", "SHA256", "SHA256-192",
    "SHA384", "SHA512", "SHA512-224", "SHA512-256",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE-128", "SHAKE-256",
    "KECCAK-KMAC-128", "KECCAK-KMAC-256"
};

/* The XOFs, which can also be serialized while they are squeezing */
static const char *xof_algs[] = {
    "SHAKE-128", "SHAKE-256", "KECCAK-KMAC-128", "KECCAK-KMAC-256"
};

/*
 * data1 is larger than the block size of every algorithm above (max. 168
 * bytes) and not a multiple of any block size, so that the chaining state is
 * non-trivial and a partial block remains buffered when the state is
 * serialized. data2 is hashed after deserializing.
 */
#define DATA1_LEN 300
#define DATA2_LEN 150
#define XOF_OUT_LEN 64
/*
 * The reinit tests hash a context that was used and finalized before, and then
 * only SHORT_LEN bytes, which is less than a block of every algorithm above, so
 * that no complete block was absorbed when the state is serialized.
 */
#define SHORT_LEN 10
/*
 * The squeeze tests output SQUEEZE1_LEN bytes before serializing, which leaves
 * a partially consumed output block (the block sizes are 136 and 168 bytes),
 * and SQUEEZE2_LEN bytes afterwards, which spans several output blocks.
 */
#define SQUEEZE1_LEN 100
#define SQUEEZE2_LEN 400

static unsigned char data1[DATA1_LEN];
static unsigned char data2[DATA2_LEN];

static const char *mode;
static const char *prefix;

static void fill_data(void)
{
    size_t i;

    for (i = 0; i < sizeof(data1); i++)
        data1[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < sizeof(data2); i++)
        data2[i] = (unsigned char)(i * 13 + 5);
}

static char *state_filename(const char *alg, const char *tag)
{
    size_t len = strlen(prefix) + 1 + strlen(alg) + 1 + strlen(tag) + 1;
    char *name = OPENSSL_malloc(len);

    if (name != NULL)
        snprintf(name, len, "%s.%s.%s", prefix, alg, tag);
    return name;
}

static int finalize(EVP_MD_CTX *ctx, const EVP_MD *md, unsigned char *out,
    size_t *outlen)
{
    unsigned int len = 0;

    if (EVP_MD_xof(md)) {
        *outlen = XOF_OUT_LEN;
        return EVP_DigestFinalXOF(ctx, out, XOF_OUT_LEN);
    }
    if (!EVP_DigestFinal_ex(ctx, out, &len))
        return 0;
    *outlen = len;
    return 1;
}

/*
 * Hash data1, finish or squeeze and initialize the same context again.
 * Platform specific implementations may keep state of the previous use in the
 * context. XOFs are squeezed instead of finalized with EVP_DigestFinalXOF(),
 * as that would also change the output length of the context.
 */
static int reuse_ctx(EVP_MD_CTX *ctx, const EVP_MD *md)
{
    unsigned char tmp[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    if (!TEST_true(EVP_DigestUpdate(ctx, data1, sizeof(data1))))
        return 0;
    if (EVP_MD_xof(md)) {
        if (!TEST_true(EVP_DigestSqueeze(ctx, tmp, XOF_OUT_LEN)))
            return 0;
    } else if (!TEST_true(EVP_DigestFinal_ex(ctx, tmp, &len))) {
        return 0;
    }
    return TEST_true(EVP_DigestInit_ex2(ctx, NULL, NULL));
}

/*
 * Serialize a context after hashing data1 (reinit = 0) or after hashing
 * SHORT_LEN bytes of data1 with a context that was used before (reinit = 1).
 */
static int write_state(int tstid, int reinit)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    char *name = NULL;
    BIO *bio = NULL;
    size_t buflen = 0;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, algs[tstid], NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || (reinit && !reuse_ctx(ctx, md))
        || !TEST_true(EVP_DigestUpdate(ctx, data1,
            reinit ? SHORT_LEN : sizeof(data1)))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, NULL, &buflen))
        || !TEST_ptr(buf = OPENSSL_malloc(buflen))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, buf, &buflen))
        || !TEST_ptr(name = state_filename(algs[tstid], reinit ? "rei" : "upd"))
        || !TEST_ptr(bio = BIO_new_file(name, "wb"))
        || !TEST_int_eq(BIO_write(bio, buf, (int)buflen), (int)buflen))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    OPENSSL_free(name);
    OPENSSL_free(buf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int test_write_state(int tstid)
{
    return write_state(tstid, 0);
}

static int test_write_reinit_state(int tstid)
{
    return write_state(tstid, 1);
}

static int read_state(int tstid, int reinit)
{
    size_t len1 = reinit ? SHORT_LEN : sizeof(data1);
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL, *ref = NULL;
    unsigned char *buf = NULL;
    unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];
    size_t d1_len = 0, d2_len = 0, buflen = 0;
    char *name = NULL;
    BIO *bio = NULL;
    int ret = 0, n;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, algs[tstid], NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_ptr(ref = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, NULL, &buflen))
        || !TEST_ptr(buf = OPENSSL_malloc(buflen))
        || !TEST_ptr(name = state_filename(algs[tstid], reinit ? "rei" : "upd"))
        || !TEST_ptr(bio = BIO_new_file(name, "rb")))
        goto end;

    n = BIO_read(bio, buf, (int)buflen);
    if (!TEST_int_eq(n, (int)buflen))
        goto end;

    /* Complete the digest from the state produced by the other process */
    if (!TEST_true(EVP_MD_CTX_deserialize(ctx, buf, buflen))
        || !TEST_true(EVP_DigestUpdate(ctx, data2, sizeof(data2)))
        || !TEST_true(finalize(ctx, md, d1, &d1_len)))
        goto end;

    /* Reference: hash everything in this process */
    if (!TEST_true(EVP_DigestInit_ex2(ref, md, NULL))
        || !TEST_true(EVP_DigestUpdate(ref, data1, len1))
        || !TEST_true(EVP_DigestUpdate(ref, data2, sizeof(data2)))
        || !TEST_true(finalize(ref, md, d2, &d2_len))
        || !TEST_mem_eq(d1, d1_len, d2, d2_len))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    OPENSSL_free(name);
    OPENSSL_free(buf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ref);
    EVP_MD_free(md);
    return ret;
}

static int test_read_state(int tstid)
{
    return read_state(tstid, 0);
}

static int test_read_reinit_state(int tstid)
{
    return read_state(tstid, 1);
}

/*
 * A context that was used and finalized before must give the same digest as a
 * new one after it was initialized again, with all implementations.
 */
static int test_reuse(int tstid)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL, *ref = NULL;
    unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];
    size_t d1_len = 0, d2_len = 0;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, algs[tstid], NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_ptr(ref = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(reuse_ctx(ctx, md))
        || !TEST_true(EVP_DigestUpdate(ctx, data2, sizeof(data2)))
        || !TEST_true(finalize(ctx, md, d1, &d1_len))
        || !TEST_true(EVP_DigestInit_ex2(ref, md, NULL))
        || !TEST_true(EVP_DigestUpdate(ref, data2, sizeof(data2)))
        || !TEST_true(finalize(ref, md, d2, &d2_len))
        || !TEST_mem_eq(d1, d1_len, d2, d2_len))
        goto end;

    ret = 1;
end:
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ref);
    EVP_MD_free(md);
    return ret;
}

/* Serialize an XOF after it has started to squeeze output */
static int test_write_squeezed_state(int tstid)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *buf = NULL;
    unsigned char out[SQUEEZE1_LEN];
    char *name = NULL;
    BIO *bio = NULL;
    size_t buflen = 0;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, xof_algs[tstid], NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_DigestUpdate(ctx, data1, sizeof(data1)))
        || !TEST_true(EVP_DigestSqueeze(ctx, out, sizeof(out)))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, NULL, &buflen))
        || !TEST_ptr(buf = OPENSSL_malloc(buflen))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, buf, &buflen))
        || !TEST_ptr(name = state_filename(xof_algs[tstid], "sqz"))
        || !TEST_ptr(bio = BIO_new_file(name, "wb"))
        || !TEST_int_eq(BIO_write(bio, buf, (int)buflen), (int)buflen))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    OPENSSL_free(name);
    OPENSSL_free(buf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

/* Continue squeezing from a state written by test_write_squeezed_state() */
static int test_read_squeezed_state(int tstid)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL, *ref = NULL;
    unsigned char *buf = NULL;
    unsigned char skip[SQUEEZE1_LEN];
    unsigned char o1[SQUEEZE2_LEN], o2[SQUEEZE2_LEN];
    size_t buflen = 0;
    char *name = NULL;
    BIO *bio = NULL;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, xof_algs[tstid], NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_ptr(ref = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_MD_CTX_serialize(ctx, NULL, &buflen))
        || !TEST_ptr(buf = OPENSSL_malloc(buflen))
        || !TEST_ptr(name = state_filename(xof_algs[tstid], "sqz"))
        || !TEST_ptr(bio = BIO_new_file(name, "rb"))
        || !TEST_int_eq(BIO_read(bio, buf, (int)buflen), (int)buflen))
        goto end;

    if (!TEST_true(EVP_MD_CTX_deserialize(ctx, buf, buflen))
        || !TEST_true(EVP_DigestSqueeze(ctx, o1, sizeof(o1))))
        goto end;

    /* Reference: squeeze everything in this process */
    if (!TEST_true(EVP_DigestInit_ex2(ref, md, NULL))
        || !TEST_true(EVP_DigestUpdate(ref, data1, sizeof(data1)))
        || !TEST_true(EVP_DigestSqueeze(ref, skip, sizeof(skip)))
        || !TEST_true(EVP_DigestSqueeze(ref, o2, sizeof(o2)))
        || !TEST_mem_eq(o1, sizeof(o1), o2, sizeof(o2)))
        goto end;

    ret = 1;
end:
    BIO_free(bio);
    OPENSSL_free(name);
    OPENSSL_free(buf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ref);
    EVP_MD_free(md);
    return ret;
}

OPT_TEST_DECLARE_USAGE("write|read file-prefix | reuse")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(mode = test_get_argument(0))) {
        TEST_error("Usage: evp_md_serialize_test write|read file-prefix | reuse\n");
        return 0;
    }

    fill_data();

    if (strcmp(mode, "reuse") == 0) {
        if (test_get_argument_count() != 1) {
            TEST_error("Usage: evp_md_serialize_test reuse\n");
            return 0;
        }
        ADD_ALL_TESTS(test_reuse, OSSL_NELEM(algs));
        return 1;
    }

    if (test_get_argument_count() != 2
        || !TEST_ptr(prefix = test_get_argument(1))) {
        TEST_error("Usage: evp_md_serialize_test write|read file-prefix\n");
        return 0;
    }

    if (strcmp(mode, "write") == 0) {
        ADD_ALL_TESTS(test_write_state, OSSL_NELEM(algs));
        ADD_ALL_TESTS(test_write_reinit_state, OSSL_NELEM(algs));
        ADD_ALL_TESTS(test_write_squeezed_state, OSSL_NELEM(xof_algs));
    } else if (strcmp(mode, "read") == 0) {
        ADD_ALL_TESTS(test_read_state, OSSL_NELEM(algs));
        ADD_ALL_TESTS(test_read_reinit_state, OSSL_NELEM(algs));
        ADD_ALL_TESTS(test_read_squeezed_state, OSSL_NELEM(xof_algs));
    } else {
        TEST_error("Unknown mode '%s'\n", mode);
        return 0;
    }
    return 1;
}
