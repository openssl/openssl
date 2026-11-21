/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "testutil.h"

/* a, b and c are distinct; a2 equals a; bad is flagged EXFLAG_INVALID. */
static X509 *a, *a2, *b, *c, *bad, *bad2;

static X509 *load_cert(const char *file)
{
    BIO *bio = BIO_new_file(file, "r");
    X509 *x = NULL;

    if (TEST_ptr(bio))
        x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x;
}

/*
 * Add @in to a stack already holding @seed, with X509_ADD_FLAG_NO_DUP, and
 * check the result is exactly @exp, pointer for pointer.
 */
static int check(X509 **seed, int nseed, X509 **in, int nin, int flags,
    X509 **exp, int nexp)
{
    STACK_OF(X509) *dst = sk_X509_new_null(), *src = sk_X509_new_null();
    int i, ret = 0;

    if (!TEST_ptr(dst) || !TEST_ptr(src))
        goto err;
    for (i = 0; i < nseed; i++)
        if (!TEST_true(X509_add_cert(dst, seed[i], X509_ADD_FLAG_UP_REF)))
            goto err;
    for (i = 0; i < nin; i++)
        if (!TEST_true(sk_X509_push(src, in[i])))
            goto err;

    if (!TEST_true(X509_add_certs(dst, src,
            flags | X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP))
        || !TEST_int_eq(sk_X509_num(dst), nexp))
        goto err;
    for (i = 0; i < nexp; i++)
        if (!TEST_ptr_eq(sk_X509_value(dst, i), exp[i]))
            goto err;
    ret = 1;
err:
    sk_X509_free(src);
    sk_X509_pop_free(dst, X509_free);
    return ret;
}

/* The first of two equal certificates is kept. */
static int test_dedup_append(void)
{
    X509 *in[] = { a, b, a2, c, b };
    X509 *exp[] = { a, b, c };

    return check(NULL, 0, in, OSSL_NELEM(in), 0, exp, OSSL_NELEM(exp));
}

/* With PREPEND the input is walked backwards, so the last one is kept. */
static int test_dedup_prepend(void)
{
    X509 *in[] = { a, b, a2, c, b };
    X509 *exp[] = { a2, c, b };

    return check(NULL, 0, in, OSSL_NELEM(in), X509_ADD_FLAG_PREPEND,
        exp, OSSL_NELEM(exp));
}

/* Deduplicating a modified certificate must not cache unfinished extensions. */
static int test_dedup_modified(void)
{
    X509 *x = X509_dup(b);
    X509 *in[] = { x, x, x, x, x };
    X509_EXTENSION *usage = NULL;
    int ret = 0;

    if (!TEST_ptr(x)
        || !TEST_ptr(usage = X509_delete_ext(x,
                         X509_get_ext_by_NID(x, NID_key_usage, -1)))
        || !check(NULL, 0, in, OSSL_NELEM(in), 0, &x, 1)
        || !TEST_true(X509_add_ext(x, usage, -1))
        || !TEST_uint_eq(X509_get_key_usage(x), X509_get_key_usage(b)))
        goto end;
    ret = 1;
end:
    X509_EXTENSION_free(usage);
    X509_free(x);
    return ret;
}

/*
 * A modified certificate in the destination does not stop the others from
 * being deduplicated, and is itself only equal to itself.
 */
static int test_dedup_modified_existing(void)
{
    X509 *x = X509_dup(b);
    X509 *seed[] = { x };
    X509 *in[] = { a, b, a2, x, c, b };
    X509 *exp[] = { x, a, b, c };
    X509_EXTENSION *usage = NULL;
    int ret = 0;

    if (!TEST_ptr(x)
        || !TEST_ptr(usage = X509_delete_ext(x,
                         X509_get_ext_by_NID(x, NID_key_usage, -1)))
        || !check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in), 0,
            exp, OSSL_NELEM(exp)))
        goto end;
    ret = 1;
end:
    X509_EXTENSION_free(usage);
    X509_free(x);
    return ret;
}

/* Certificates already in the destination are not added again. */
static int test_dedup_existing(void)
{
    X509 *seed[] = { b };
    X509 *in[] = { a, b, c };
    X509 *exp[] = { b, a, c };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in), 0,
        exp, OSSL_NELEM(exp));
}

/* Skipping the hash path must leave the caller's error mark intact. */
static int test_dedup_small_error_mark(void)
{
    X509 *in[] = { a, a2 };
    X509 *exp[] = { a };
    unsigned long marked_error;
    int ret = 0;

    ERR_raise(ERR_LIB_USER, 1);
    marked_error = ERR_peek_last_error();
    if (!TEST_true(ERR_set_mark()))
        goto end;
    ERR_raise(ERR_LIB_USER, 2);
    if (!check(NULL, 0, in, OSSL_NELEM(in), 0, exp, OSSL_NELEM(exp))
        || !TEST_true(ERR_pop_to_mark())
        || !TEST_ulong_eq(ERR_peek_last_error(), marked_error))
        goto end;
    ret = 1;
end:
    ERR_clear_error();
    return ret;
}

/*
 * A certificate with an invalid extension is deduplicated like any other,
 * and the call leaves no error behind.
 */
static int test_dedup_invalid(void)
{
    X509 *in[] = { bad, a, bad2, a, bad };
    X509 *exp[] = { bad, a };

    if (!TEST_true(X509_get_extension_flags(bad) & EXFLAG_INVALID))
        return 0;
    ERR_clear_error();
    return check(NULL, 0, in, OSSL_NELEM(in), 0, exp, OSSL_NELEM(exp))
        && TEST_ulong_eq(ERR_peek_error(), 0);
}

OPT_TEST_DECLARE_USAGE("cert1.pem cert2.pem cert3.pem invalid.pem\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_size_t_eq(test_get_argument_count(), 4)
        || !TEST_ptr(a = load_cert(test_get_argument(0)))
        || !TEST_ptr(b = load_cert(test_get_argument(1)))
        || !TEST_ptr(c = load_cert(test_get_argument(2)))
        || !TEST_ptr(bad = load_cert(test_get_argument(3)))
        || !TEST_ptr(a2 = X509_dup(a))
        || !TEST_ptr(bad2 = X509_dup(bad)))
        return 0;

    ADD_TEST(test_dedup_append);
    ADD_TEST(test_dedup_prepend);
    ADD_TEST(test_dedup_modified);
    ADD_TEST(test_dedup_modified_existing);
    ADD_TEST(test_dedup_existing);
    ADD_TEST(test_dedup_small_error_mark);
    ADD_TEST(test_dedup_invalid);
    return 1;
}

void cleanup_tests(void)
{
    X509_free(a);
    X509_free(a2);
    X509_free(b);
    X509_free(c);
    X509_free(bad);
    X509_free(bad2);
}
