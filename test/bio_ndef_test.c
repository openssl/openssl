/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests of BIO_new_NDEF() against a minimal streamable ASN.1 structure,
 * independent of CMS and PKCS7.  The structure's callback implements the
 * stream operations described in ASN1_aux_cb(3), and can be made to
 * misbehave in ways a third-party callback plausibly would, to pin down
 * how BIO_new_NDEF() holds up.  See also BIO_new_NDEF(3).
 */

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "testutil.h"

typedef struct {
    ASN1_OCTET_STRING *content;
} NDEF_TEST_VAL;

DECLARE_ASN1_FUNCTIONS(NDEF_TEST_VAL)

/* How ndef_test_cb() behaves; a well written callback uses CB_NORMAL */
enum {
    CB_NORMAL,
    CB_FAIL_STREAM_PRE, /* fail ASN1_OP_STREAM_PRE */
    CB_NO_CONTENT, /* leave ASN1_OP_GET0_STREAM_CONTENT unhandled */
    CB_CONTENT_THEN_FAIL /* store the content string, then report failure */
};
static int cb_mode = CB_NORMAL;

static int ndef_test_cb(int operation, ASN1_VALUE **pval,
    const ASN1_ITEM *it, void *exarg)
{
    NDEF_TEST_VAL *v = (NDEF_TEST_VAL *)*pval;
    ASN1_STREAM_ARG *sarg = exarg;

    switch (operation) {
    case ASN1_OP_STREAM_PRE:
        if (cb_mode == CB_FAIL_STREAM_PRE || v->content == NULL)
            return 0;
        /* Nothing to digest or encrypt: stream straight through */
        sarg->ndef_bio = sarg->out;
        break;

    case ASN1_OP_GET0_STREAM_CONTENT:
        if (cb_mode == CB_NO_CONTENT)
            break;
        *(ASN1_STRING **)exarg = v->content;
        if (cb_mode == CB_CONTENT_THEN_FAIL)
            return 0;
        break;
    }
    return 1;
}

ASN1_NDEF_SEQUENCE_cb(NDEF_TEST_VAL, ndef_test_cb) = {
    ASN1_SIMPLE(NDEF_TEST_VAL, content, ASN1_OCTET_STRING_NDEF)
} ASN1_NDEF_SEQUENCE_END_cb(NDEF_TEST_VAL, NDEF_TEST_VAL)

IMPLEMENT_ASN1_FUNCTIONS(NDEF_TEST_VAL)

static const unsigned char payload[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define PAYLOAD_LEN ((int)sizeof(payload) - 1)
#define PAYLOAD_SPLIT 10

/* Free the filter BIOs down to, but not including, out */
static void free_filter_bios(BIO *bio, BIO *out)
{
    while (bio != NULL && bio != out) {
        BIO *next = BIO_pop(bio);

        BIO_free(bio);
        bio = next;
    }
}

/* Stream a payload in two writes and check that it round-trips */
static int test_ndef_stream_ok(void)
{
    NDEF_TEST_VAL *v = NULL, *parsed = NULL;
    BIO *out = NULL, *bio = NULL;
    unsigned char *encoded = NULL;
    const unsigned char *der;
    long encoded_len;
    int ret = 0;

    cb_mode = CB_NORMAL;

    if (!TEST_ptr(v = NDEF_TEST_VAL_new())
        || !TEST_ptr(out = BIO_new(BIO_s_mem()))
        || !TEST_ptr(bio = BIO_new_NDEF(out, (ASN1_VALUE *)v,
                         ASN1_ITEM_rptr(NDEF_TEST_VAL))))
        goto err;

    if (!TEST_int_eq(BIO_write(bio, payload, PAYLOAD_SPLIT), PAYLOAD_SPLIT)
        || !TEST_int_eq(BIO_write(bio, payload + PAYLOAD_SPLIT,
                            PAYLOAD_LEN - PAYLOAD_SPLIT),
            PAYLOAD_LEN - PAYLOAD_SPLIT)
        || !TEST_int_gt(BIO_flush(bio), 0))
        goto err;

    free_filter_bios(bio, out);
    bio = NULL;

    encoded_len = BIO_get_mem_data(out, &encoded);
    if (!TEST_long_gt(encoded_len, 0))
        goto err;

    der = encoded;
    if (!TEST_ptr(parsed = d2i_NDEF_TEST_VAL(NULL, &der, encoded_len))
        || !TEST_mem_eq(ASN1_STRING_get0_data(parsed->content),
            ASN1_STRING_get_length(parsed->content),
            payload, PAYLOAD_LEN))
        goto err;

    ret = 1;
err:
    free_filter_bios(bio, out);
    BIO_free(out);
    NDEF_TEST_VAL_free(parsed);
    NDEF_TEST_VAL_free(v);
    return ret;
}

/* An item with no callback cannot stream; out must stay usable */
static int test_ndef_not_supported(void)
{
    ASN1_OCTET_STRING *os = NULL;
    BIO *out = NULL;
    int ret = 0;

    if (!TEST_ptr(os = ASN1_OCTET_STRING_new())
        || !TEST_ptr(out = BIO_new(BIO_s_mem())))
        goto err;

    ERR_clear_error();
    if (!TEST_ptr_null(BIO_new_NDEF(out, (ASN1_VALUE *)os,
            ASN1_ITEM_rptr(ASN1_OCTET_STRING)))
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            ASN1_R_STREAMING_NOT_SUPPORTED))
        goto err;

    /* On failure out remains owned by the caller and usable */
    if (!TEST_int_eq(BIO_write(out, "x", 1), 1))
        goto err;

    ret = 1;
err:
    BIO_free(out);
    ASN1_OCTET_STRING_free(os);
    return ret;
}

/* A failed ASN1_OP_STREAM_PRE must unwind the half-built chain */
static int test_ndef_stream_pre_fails(void)
{
    NDEF_TEST_VAL *v = NULL;
    BIO *out = NULL;
    int ret = 0;

    cb_mode = CB_FAIL_STREAM_PRE;

    if (!TEST_ptr(v = NDEF_TEST_VAL_new())
        || !TEST_ptr(out = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_ptr_null(BIO_new_NDEF(out, (ASN1_VALUE *)v,
            ASN1_ITEM_rptr(NDEF_TEST_VAL))))
        goto err;

    /* On failure out remains owned by the caller and usable */
    if (!TEST_int_eq(BIO_write(out, "x", 1), 1))
        goto err;

    ret = 1;
err:
    cb_mode = CB_NORMAL;
    BIO_free(out);
    NDEF_TEST_VAL_free(v);
    return ret;
}

/*
 * A callback that does not provide the content string, either by leaving
 * ASN1_OP_GET0_STREAM_CONTENT unhandled (idx 0, the shape of a callback written
 * before that operation existed) or by storing the string and then
 * reporting failure (idx 1).  Setting up the BIO chain still succeeds,
 * because the stream callbacks have already modified it, but the first
 * write must fail cleanly instead of encoding through a content string
 * that the encoder is not recording the content position in.
 */
static int test_ndef_content_missing(int idx)
{
    NDEF_TEST_VAL *v = NULL;
    BIO *out = NULL, *bio = NULL;
    int ret = 0;

    cb_mode = idx == 0 ? CB_NO_CONTENT : CB_CONTENT_THEN_FAIL;

    /* Content with data present makes a stale-position mistake detectable */
    if (!TEST_ptr(v = NDEF_TEST_VAL_new())
        || !TEST_true(ASN1_OCTET_STRING_set(v->content, payload, PAYLOAD_LEN))
        || !TEST_ptr(out = BIO_new(BIO_s_mem()))
        || !TEST_ptr(bio = BIO_new_NDEF(out, (ASN1_VALUE *)v,
                         ASN1_ITEM_rptr(NDEF_TEST_VAL))))
        goto err;

    if (!TEST_int_le(BIO_write(bio, payload, PAYLOAD_LEN), 0))
        goto err;

    ret = 1;
err:
    cb_mode = CB_NORMAL;
    free_filter_bios(bio, out);
    BIO_free(out);
    NDEF_TEST_VAL_free(v);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_ndef_stream_ok);
    ADD_TEST(test_ndef_not_supported);
    ADD_TEST(test_ndef_stream_pre_fails);
    ADD_ALL_TESTS(test_ndef_content_missing, 2);
    return 1;
}
