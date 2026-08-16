/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "testutil.h"

/*-
 * Sweep a corpus of EC parameter files, exercising what the ecparam and
 * pkeyparam applications do to each one.  The applications are covered
 * separately in 20-test_app_ecparam.t; running the whole corpus through
 * them costs a process per file per check, which is startup time rather
 * than test coverage.
 *
 * Invoked as:
 *
 *     ecparam_test valid|noncanon|invalid <file>...
 *
 * Valid and non-canonically encoded parameters must load and check.
 * Invalid ones must not.  Only the canonically encoded valid files are
 * expected to re-encode to exactly the bytes they were read from.
 */
typedef enum {
    CORPUS_VALID,
    CORPUS_NONCANON,
    CORPUS_INVALID
} corpus_kind;

static corpus_kind corpus;
static int expect_check; /* Whether loading and checking should succeed */
static int num_files;

/* The files start at argument 1; argument 0 names the corpus. */
static const char *corpus_file(int idx)
{
    return test_get_argument(idx + 1);
}

/*
 * Load domain parameters the way the applications do.  ecparam insists the
 * result be an EC or SM2 key, pkeyparam takes whatever it is given.
 */
static EVP_PKEY *load_params(const char *file, int ec_only)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *bio = BIO_new_file(file, "rb");

    if (bio == NULL)
        return NULL;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL,
        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, NULL, NULL);
    if (dctx == NULL) {
        BIO_free(bio);
        return NULL;
    }

    if (!OSSL_DECODER_from_bio(dctx, bio)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);

    if (pkey != NULL && ec_only
        && !EVP_PKEY_is_a(pkey, "EC") && !EVP_PKEY_is_a(pkey, "SM2")) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}

/* Run EVP_PKEY_param_check() as the applications do after loading. */
static int check_params(EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    int ret;

    if (ctx == NULL)
        return 0;

    ret = EVP_PKEY_param_check(ctx) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Load and check, optionally restricting the check to named curves as
 * "ecparam -check_named" does.  Returns 1 if the outcome matched what the
 * corpus expects.
 */
static int load_and_check(int idx, int ec_only, int named)
{
    const char *file = corpus_file(idx);
    EVP_PKEY *pkey = load_params(file, ec_only);
    int ok;

    if (pkey == NULL)
        return TEST_int_eq(expect_check, 0);

    if (named
        && !TEST_true(EVP_PKEY_set_utf8_string_param(pkey,
            OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
            OSSL_PKEY_EC_GROUP_CHECK_NAMED))) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    ok = check_params(pkey);
    EVP_PKEY_free(pkey);

    if (!TEST_int_eq(ok, expect_check)) {
        TEST_info("%s", file);
        return 0;
    }
    return 1;
}

static int test_ecparam_check(int idx)
{
    return load_and_check(idx, 1, 0);
}

static int test_ecparam_check_named(int idx)
{
    return load_and_check(idx, 1, 1);
}

static int test_pkeyparam_check(int idx)
{
    return load_and_check(idx, 0, 0);
}

/* Read a whole file, so the re-encoded form can be compared against it. */
static int read_file(const char *file, unsigned char **out, long *out_len)
{
    BIO *bio = BIO_new_file(file, "rb");
    unsigned char *buf = NULL;
    long len = 0, n, i, j;

    if (bio == NULL)
        return 0;

    for (;;) {
        unsigned char *tmp = OPENSSL_realloc(buf, (size_t)len + 4096);

        if (tmp == NULL) {
            OPENSSL_free(buf);
            BIO_free(bio);
            return 0;
        }
        buf = tmp;
        n = BIO_read(bio, buf + len, 4096);
        if (n <= 0)
            break;
        len += n;
    }

    BIO_free(bio);

    for (i = 0, j = 0; i < len; i++)
        if (buf[i] != '\r')
            buf[j++] = buf[i];

    *out = buf;
    *out_len = j;
    return 1;
}

/*
 * Canonically encoded parameters must survive a decode and re-encode
 * unchanged, which is what "ecparam -in x -out y" is checked to do.
 */
static int test_reencode(int idx)
{
    const char *file = corpus_file(idx);
    EVP_PKEY *pkey = load_params(file, 1);
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem = NULL;
    unsigned char *orig = NULL;
    char *enc = NULL;
    long orig_len = 0;
    long enc_len;
    int ret = 0;

    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto err;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,
        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM", NULL, NULL);
    if (!TEST_ptr(ectx) || !TEST_true(OSSL_ENCODER_to_bio(ectx, mem)))
        goto err;

    if (!TEST_true(read_file(file, &orig, &orig_len)))
        goto err;

    enc_len = BIO_get_mem_data(mem, &enc);
    if (!TEST_mem_eq(enc, (size_t)enc_len, orig, (size_t)orig_len)) {
        TEST_info("%s", file);
        goto err;
    }

    ret = 1;
err:
    OPENSSL_free(orig);
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    const char *kind;
    size_t argc = test_get_argument_count();

    if (!TEST_size_t_gt(argc, 1)) {
        TEST_error("usage: ecparam_test valid|noncanon|invalid <file>...");
        return 0;
    }

    kind = test_get_argument(0);
    if (strcmp(kind, "valid") == 0) {
        corpus = CORPUS_VALID;
    } else if (strcmp(kind, "noncanon") == 0) {
        corpus = CORPUS_NONCANON;
    } else if (strcmp(kind, "invalid") == 0) {
        corpus = CORPUS_INVALID;
    } else {
        TEST_error("unknown corpus \"%s\"", kind);
        return 0;
    }

    expect_check = corpus != CORPUS_INVALID;
    num_files = (int)argc - 1;

    ADD_ALL_TESTS(test_ecparam_check, num_files);
    ADD_ALL_TESTS(test_ecparam_check_named, num_files);
    ADD_ALL_TESTS(test_pkeyparam_check, num_files);
    /* Only the canonical encodings are expected to be byte stable. */
    if (corpus == CORPUS_VALID)
        ADD_ALL_TESTS(test_reencode, num_files);

    return 1;
}
