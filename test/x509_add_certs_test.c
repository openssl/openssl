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

#include "crypto/x509.h" /* x509_st definition, for the reference count */
#include "testutil.h"

/*
 * a, b and c are distinct; a2 equals a; bad is flagged EXFLAG_INVALID; c is
 * self-signed.
 */
static X509 *a, *a2, *b, *c, *bad, *bad2;

/* Distinct certificates with cached extensions, for the mfail test. */
#define NMANY 24
static X509 *many[NMANY];

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

/*
 * Certificates already in the destination are not added again. More than
 * four inputs, so that the hash table is used.
 */
static int test_dedup_existing(void)
{
    X509 *seed[] = { b };
    X509 *in[] = { a, b, c, a2, b };
    X509 *exp[] = { b, a, c };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in), 0,
        exp, OSSL_NELEM(exp));
}

/*
 * A destination of more than four certificates selects the hash table even
 * for a short input. The destination is taken as is, duplicates included.
 */
static int test_dedup_large_existing(void)
{
    X509 *seed[] = { b, c, bad, b, c };
    X509 *in[] = { a, a2, b };
    X509 *exp[] = { b, c, bad, b, c, a };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in), 0,
        exp, OSSL_NELEM(exp));
}

/*
 * With PREPEND and a non-empty destination, the input is walked backwards
 * and certificates already in the destination are skipped.
 */
static int test_dedup_prepend_existing(void)
{
    X509 *seed[] = { b };
    X509 *in[] = { a, b, a2, c, b };
    X509 *exp[] = { a2, c, b };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in),
        X509_ADD_FLAG_PREPEND, exp, OSSL_NELEM(exp));
}

/*
 * PREPEND with a short input and a destination of more than four
 * certificates, so the destination selects the hash table. The input is
 * walked backwards, so of a and a2 the later one is kept.
 */
static int test_dedup_prepend_large_existing(void)
{
    X509 *seed[] = { b, bad, b, bad, b };
    X509 *in[] = { a, c, b, a2 };
    X509 *exp[] = { c, a2, b, bad, b, bad, b };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in),
        X509_ADD_FLAG_PREPEND, exp, OSSL_NELEM(exp));
}

/*
 * When every input is already in the destination, the call succeeds and
 * leaves the destination and all reference counts unchanged.
 */
static int test_dedup_all_existing(void)
{
    X509 *seed[] = { a, b, c, bad };
    X509 *in[] = { a2, b, c, bad2, a };

    return check(seed, OSSL_NELEM(seed), in, OSSL_NELEM(in), 0,
        seed, OSSL_NELEM(seed));
}

/*
 * With NO_SS, self-signed certificates are dropped after deduplication, as
 * the linear scan does, when appending (idx 0) and when prepending (idx 1).
 */
static int test_dedup_no_ss(int idx)
{
    X509 *in[] = { a, c, b, a2, c, b };
    X509 *exp_append[] = { a, b };
    X509 *exp_prepend[] = { a2, b };

    if (!TEST_int_eq(X509_self_signed(c, 0), 1)
        || !TEST_int_eq(X509_self_signed(a, 0), 0)
        || !TEST_int_eq(X509_self_signed(b, 0), 0))
        return 0;
    return check(NULL, 0, in, OSSL_NELEM(in),
        X509_ADD_FLAG_NO_SS | (idx == 0 ? 0 : X509_ADD_FLAG_PREPEND),
        idx == 0 ? exp_append : exp_prepend, 2);
}

/*
 * A NULL certificate on the hash path fails the call before anything is
 * added to the destination.
 */
static int test_dedup_null(void)
{
    STACK_OF(X509) *dst = sk_X509_new_null(), *src = sk_X509_new_null();
    X509 *in[] = { a, b, NULL, c, a2 };
    size_t i;
    int ret = 0;

    if (!TEST_ptr(dst) || !TEST_ptr(src)
        || !TEST_true(X509_add_cert(dst, c, X509_ADD_FLAG_UP_REF)))
        goto err;
    for (i = 0; i < OSSL_NELEM(in); i++)
        if (!TEST_true(sk_X509_push(src, in[i])))
            goto err;

    if (!TEST_false(X509_add_certs(dst, src,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP))
        || !TEST_int_eq(sk_X509_num(dst), 1)
        || !TEST_ptr_eq(sk_X509_value(dst, 0), c))
        goto err;
    ret = 1;
err:
    sk_X509_free(src);
    sk_X509_pop_free(dst, X509_free);
    return ret;
}

/* A certificate with an invalid extension is deduplicated like any other. */
static int test_dedup_invalid(void)
{
    X509 *in[] = { bad, a, bad2, a, bad };
    X509 *exp[] = { bad, a };

    if (!TEST_true(X509_get_extension_flags(bad) & EXFLAG_INVALID))
        return 0;
    return check(NULL, 0, in, OSSL_NELEM(in), 0, exp, OSSL_NELEM(exp));
}

/*
 * Deduplicate through the hash table with an uncached certificate that has
 * an invalid extension, so that caching it raises an error.
 */
static int dedup_uncached_invalid(void)
{
    X509 *x = X509_dup(bad);
    X509 *in[] = { x, a, b, a2, c };
    X509 *exp[] = { x, a, b, c };
    int ret;

    ret = TEST_ptr(x)
        && check(NULL, 0, in, OSSL_NELEM(in), 0, exp, OSSL_NELEM(exp));
    X509_free(x);
    return ret;
}

/*
 * A successful call keeps the caller's errors, in order, and the caller's
 * mark. The only error it may add is the one for the invalid certificate.
 */
static int test_dedup_error_mark(void)
{
    unsigned long err1, err2, e;
    int ret = 0;

    ERR_clear_error();

    /* The errors below and above the mark survive, in order. */
    ERR_raise(ERR_LIB_USER, 1);
    err1 = ERR_peek_last_error();
    if (!TEST_true(ERR_set_mark()))
        goto end;
    ERR_raise(ERR_LIB_USER, 2);
    err2 = ERR_peek_last_error();
    if (!dedup_uncached_invalid()
        || !TEST_ulong_eq(ERR_get_error(), err1)
        || !TEST_ulong_eq(ERR_get_error(), err2))
        goto end;
    while ((e = ERR_get_error()) != 0)
        if (!TEST_int_eq(ERR_GET_LIB(e), ERR_LIB_X509V3)
            || !TEST_int_eq(ERR_GET_REASON(e), X509V3_R_INVALID_CERTIFICATE))
            goto end;

    /* The mark survives: popping to it leaves just the marked error. */
    ERR_raise(ERR_LIB_USER, 1);
    err1 = ERR_peek_last_error();
    if (!TEST_true(ERR_set_mark()))
        goto end;
    ERR_raise(ERR_LIB_USER, 2);
    if (!dedup_uncached_invalid()
        || !TEST_true(ERR_pop_to_mark())
        || !TEST_ulong_eq(ERR_peek_error(), err1)
        || !TEST_ulong_eq(ERR_peek_last_error(), err1))
        goto end;
    ret = 1;
end:
    ERR_clear_error();
    return ret;
}

/*
 * Allocation failures while building the table (the table itself, the keep
 * array, its nodes and its expansion) fail the call and leave the
 * destination and all reference counts unchanged. The certificates have
 * cached extensions and the destination has room reserved, so that the
 * only allocations under MFAIL are those of the deduplication.
 *
 * The mfail driver expects 0 whenever a failure was injected, so a failed
 * call that left the state changed returns 1 to be reported.
 */
static int test_dedup_mfail(void)
{
    STACK_OF(X509) *dst = sk_X509_new_reserve(NULL, NMANY);
    STACK_OF(X509) *src = sk_X509_new_null();
    int i, r = -1, ok = 0;

    if (!TEST_ptr(dst) || !TEST_ptr(src))
        goto end;
    /* The destination holds many[0..9]; the input many[5..23] and many[0]. */
    for (i = 0; i < 10; i++)
        if (!TEST_true(X509_add_cert(dst, many[i], X509_ADD_FLAG_UP_REF)))
            goto end;
    for (i = 5; i < NMANY; i++)
        if (!TEST_true(sk_X509_push(src, many[i])))
            goto end;
    if (!TEST_true(sk_X509_push(src, many[0])))
        goto end;

    MFAIL_start();
    r = X509_add_certs(dst, src, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP);
    MFAIL_end();

    /* On success many[10..23] were appended once each, else nothing. */
    if (!TEST_int_eq(sk_X509_num(dst), r == 1 ? NMANY : 10))
        goto end;
    for (i = 0; i < NMANY; i++) {
        if (i < sk_X509_num(dst)
            && !TEST_ptr_eq(sk_X509_value(dst, i), many[i]))
            goto end;
    }
    ok = 1;
end:
    sk_X509_free(src);
    sk_X509_pop_free(dst, X509_free);
    if (r < 0)
        return 0;
    return r == 1 ? ok : !ok;
}

/*
 * A certificate equal to no other: @tmpl with serial number @serial, decoded
 * afresh and with its extensions cached.
 */
static X509 *make_distinct(const X509 *tmpl, long serial)
{
    X509 *x = X509_dup(tmpl), *ret = NULL;
    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    unsigned char *der = NULL;
    const unsigned char *p;
    int len = 0;

    if (x != NULL && sn != NULL
        && ASN1_INTEGER_set(sn, serial)
        && X509_set_serialNumber(x, sn)
        && (len = i2d_X509(x, &der)) > 0) {
        p = der;
        ret = d2i_X509(NULL, &p, len);
    }
    if (ret != NULL)
        (void)X509_check_purpose(ret, -1, 0);
    OPENSSL_free(der);
    ASN1_INTEGER_free(sn);
    X509_free(x);
    return ret;
}

OPT_TEST_DECLARE_USAGE("cert1.pem cert2.pem cert3.pem invalid.pem\n")

int setup_tests(void)
{
    int i;

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
    for (i = 0; i < NMANY; i++)
        if (!TEST_ptr(many[i] = make_distinct(a, 1000 + i)))
            return 0;

    ADD_TEST(test_dedup_append);
    ADD_TEST(test_dedup_prepend);
    ADD_TEST(test_dedup_modified);
    ADD_TEST(test_dedup_modified_existing);
    ADD_TEST(test_dedup_existing);
    ADD_TEST(test_dedup_large_existing);
    ADD_TEST(test_dedup_prepend_existing);
    ADD_TEST(test_dedup_prepend_large_existing);
    ADD_TEST(test_dedup_all_existing);
    ADD_ALL_TESTS(test_dedup_no_ss, 2);
    ADD_TEST(test_dedup_null);
    ADD_TEST(test_dedup_invalid);
    ADD_TEST(test_dedup_error_mark);
    ADD_MFAIL_TEST(test_dedup_mfail);
    return 1;
}

void cleanup_tests(void)
{
    int i;

    for (i = 0; i < NMANY; i++)
        X509_free(many[i]);
    X509_free(a);
    X509_free(a2);
    X509_free(b);
    X509_free(c);
    X509_free(bad);
    X509_free(bad2);
}
