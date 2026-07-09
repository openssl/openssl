/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "internal/numbers.h"
#include "internal/asn1.h"
#include "testutil.h"

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

/* Badly coded ASN.1 INTEGER zero wrapped in a sequence */
static unsigned char t_invalid_zero[] = {
    0x30, 0x02, /* SEQUENCE tag + length */
    0x02, 0x00 /* INTEGER tag + length */
};

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* LONG case ************************************************************* */

typedef struct {
    long test_long;
} ASN1_LONG_DATA;

ASN1_SEQUENCE(ASN1_LONG_DATA) = {
    ASN1_EMBED(ASN1_LONG_DATA, test_long, LONG),
} static_ASN1_SEQUENCE_END(ASN1_LONG_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_LONG_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_LONG_DATA)

static int test_long(void)
{
    const unsigned char *p = t_invalid_zero;
    ASN1_LONG_DATA *dectst = d2i_ASN1_LONG_DATA(NULL, &p, sizeof(t_invalid_zero));

    if (dectst == NULL)
        return 0; /* Fail */

    ASN1_LONG_DATA_free(dectst);
    return 1;
}
#endif

/* INT32 case ************************************************************* */

typedef struct {
    int32_t test_int32;
} ASN1_INT32_DATA;

ASN1_SEQUENCE(ASN1_INT32_DATA) = {
    ASN1_EMBED(ASN1_INT32_DATA, test_int32, INT32),
} static_ASN1_SEQUENCE_END(ASN1_INT32_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_INT32_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_INT32_DATA)

static int test_int32(void)
{
    const unsigned char *p = t_invalid_zero;
    ASN1_INT32_DATA *dectst = d2i_ASN1_INT32_DATA(NULL, &p, sizeof(t_invalid_zero));

    if (dectst == NULL)
        return 0; /* Fail */

    ASN1_INT32_DATA_free(dectst);
    return 1;
}

/* UINT32 case ************************************************************* */

typedef struct {
    uint32_t test_uint32;
} ASN1_UINT32_DATA;

ASN1_SEQUENCE(ASN1_UINT32_DATA) = {
    ASN1_EMBED(ASN1_UINT32_DATA, test_uint32, UINT32),
} static_ASN1_SEQUENCE_END(ASN1_UINT32_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_UINT32_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_UINT32_DATA)

static int test_uint32(void)
{
    const unsigned char *p = t_invalid_zero;
    ASN1_UINT32_DATA *dectst = d2i_ASN1_UINT32_DATA(NULL, &p, sizeof(t_invalid_zero));

    if (dectst == NULL)
        return 0; /* Fail */

    ASN1_UINT32_DATA_free(dectst);
    return 1;
}

/* INT64 case ************************************************************* */

typedef struct {
    int64_t test_int64;
} ASN1_INT64_DATA;

ASN1_SEQUENCE(ASN1_INT64_DATA) = {
    ASN1_EMBED(ASN1_INT64_DATA, test_int64, INT64),
} static_ASN1_SEQUENCE_END(ASN1_INT64_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_INT64_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_INT64_DATA)

static int test_int64(void)
{
    const unsigned char *p = t_invalid_zero;
    ASN1_INT64_DATA *dectst = d2i_ASN1_INT64_DATA(NULL, &p, sizeof(t_invalid_zero));

    if (dectst == NULL)
        return 0; /* Fail */

    ASN1_INT64_DATA_free(dectst);
    return 1;
}

/* UINT64 case ************************************************************* */

typedef struct {
    uint64_t test_uint64;
} ASN1_UINT64_DATA;

ASN1_SEQUENCE(ASN1_UINT64_DATA) = {
    ASN1_EMBED(ASN1_UINT64_DATA, test_uint64, UINT64),
} static_ASN1_SEQUENCE_END(ASN1_UINT64_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_UINT64_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_UINT64_DATA)

static int test_uint64(void)
{
    const unsigned char *p = t_invalid_zero;
    ASN1_UINT64_DATA *dectst = d2i_ASN1_UINT64_DATA(NULL, &p, sizeof(t_invalid_zero));

    if (dectst == NULL)
        return 0; /* Fail */

    ASN1_UINT64_DATA_free(dectst);
    return 1;
}

/* GeneralizedTime underflow *********************************************** */

static int test_gentime(void)
{
    /* Underflowing GeneralizedTime 161208193400Z (YYMMDDHHMMSSZ) */
    const unsigned char der[] = {
        0x18, 0x0d, 0x31, 0x36, 0x31, 0x32, 0x30, 0x38, 0x31, 0x39,
        0x33, 0x34, 0x30, 0x30, 0x5a
    };
    const unsigned char *p;
    int der_len, rc = 1;
    ASN1_GENERALIZEDTIME *gentime;

    p = der;
    der_len = sizeof(der);
    gentime = d2i_ASN1_GENERALIZEDTIME(NULL, &p, der_len);

    if (!TEST_ptr_null(gentime))
        rc = 0; /* fail */

    ASN1_GENERALIZEDTIME_free(gentime);
    return rc;
}

/* UTCTime underflow ******************************************************* */

static int test_utctime(void)
{
    /* Underflowing UTCTime 0205104700Z (MMDDHHMMSSZ) */
    const unsigned char der[] = {
        0x17, 0x0b, 0x30, 0x32, 0x30, 0x35, 0x31, 0x30, 0x34, 0x37,
        0x30, 0x30, 0x5a
    };
    const unsigned char *p;
    int der_len, rc = 1;
    ASN1_UTCTIME *utctime;

    p = der;
    der_len = sizeof(der);
    utctime = d2i_ASN1_UTCTIME(NULL, &p, der_len);

    if (!TEST_ptr_null(utctime))
        rc = 0; /* fail */

    ASN1_UTCTIME_free(utctime);
    return rc;
}

/* Invalid template ******************************************************** */

typedef struct {
    ASN1_STRING *invalidDirString;
} INVALIDTEMPLATE;

ASN1_SEQUENCE(INVALIDTEMPLATE) = {
    /*
     * DirectoryString is a CHOICE type so it must use explicit tagging -
     * but we deliberately use implicit here, which makes this template invalid.
     */
    ASN1_IMP(INVALIDTEMPLATE, invalidDirString, DIRECTORYSTRING, 12)
} static_ASN1_SEQUENCE_END(INVALIDTEMPLATE)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(INVALIDTEMPLATE)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(INVALIDTEMPLATE)

/* Empty sequence for invalid template test */
static unsigned char t_invalid_template[] = {
    0x30, 0x03, /* SEQUENCE tag + length */
    0x0c, 0x01, 0x41 /* UTF8String, length 1, "A" */
};

static int test_invalid_template(void)
{
    const unsigned char *p = t_invalid_template;
    INVALIDTEMPLATE *tmp = d2i_INVALIDTEMPLATE(NULL, &p,
        sizeof(t_invalid_template));

    /* We expect a NULL pointer return */
    if (TEST_ptr_null(tmp))
        return 1;

    INVALIDTEMPLATE_free(tmp);
    return 0;
}

static int test_reuse_asn1_object(void)
{
    static unsigned char cn_der[] = { 0x06, 0x03, 0x55, 0x04, 0x06 };
    static unsigned char oid_der[] = {
        0x06, 0x06, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    int ret = 0;
    ASN1_OBJECT *obj;
    unsigned char const *p = oid_der;

    /* Create an object that owns dynamically allocated 'sn' and 'ln' fields */

    if (!TEST_ptr(obj = ASN1_OBJECT_create(NID_undef, cn_der, sizeof(cn_der),
                      "C", "countryName")))
        goto err;
    /* reuse obj - this should not leak sn and ln */
    if (!TEST_ptr(d2i_ASN1_OBJECT(&obj, &p, sizeof(oid_der))))
        goto err;
    ret = 1;
err:
    ASN1_OBJECT_free(obj);
    return ret;
}

/*
 * A minimal, complete DER object: SEQUENCE { INTEGER 0 }.
 * asn1_d2i_read_bio() should consume exactly these bytes.
 */
static const unsigned char one_obj[] = {
    0x30, 0x03, /* SEQUENCE, length 3 */
    0x02, 0x01, 0x00 /*   INTEGER 0        */
};

/*
 * Reading concatenated DER objects from a BIO must stop cleanly at EOF:
 * once the input is exhausted on an object boundary, asn1_d2i_read_bio()
 * returns < 0 and must NOT leave an error on the queue.  Callers that loop
 * over concatenated values (e.g. CPython's ssl module loading the Windows
 * certificate store via d2i_X509_bio()) rely on this to detect end-of-input;
 * a spurious ASN1_R_NOT_ENOUGH_DATA there is reported as a fatal error.
 */
static int test_d2i_read_bio_clean_eof(void)
{
    unsigned char two_objs[sizeof(one_obj) * 2];
    BIO *bio = NULL;
    BUF_MEM *buf = NULL;
    int ret = 0;

    memcpy(two_objs, one_obj, sizeof(one_obj));
    memcpy(two_objs + sizeof(one_obj), one_obj, sizeof(one_obj));

    if (!TEST_ptr(bio = BIO_new_mem_buf(two_objs, sizeof(two_objs))))
        goto err;
    ERR_clear_error();

    /* Both complete objects are read, one per call. */
    if (!TEST_int_eq(asn1_d2i_read_bio(bio, &buf), (int)sizeof(one_obj)))
        goto err;
    BUF_MEM_free(buf);
    buf = NULL;
    if (!TEST_int_eq(asn1_d2i_read_bio(bio, &buf), (int)sizeof(one_obj)))
        goto err;
    BUF_MEM_free(buf);
    buf = NULL;

    /* Clean EOF: failure return, but no error must be queued. */
    if (!TEST_int_lt(asn1_d2i_read_bio(bio, &buf), 0))
        goto err;
    if (!TEST_ulong_eq(ERR_peek_error(), 0))
        goto err;

    ret = 1;
err:
    BUF_MEM_free(buf);
    BIO_free(bio);
    return ret;
}

/*
 * In contrast, hitting EOF in the middle of an object is genuine truncation
 * and must still be reported as ASN1_R_NOT_ENOUGH_DATA.
 */
static int test_d2i_read_bio_truncated(void)
{
    static const unsigned char truncated[] = {
        0x30, 0x05, /* SEQUENCE claims 5 content bytes ... */
        0x02, 0x01 /* ... but only 2 are present         */
    };
    BIO *bio = NULL;
    BUF_MEM *buf = NULL;
    unsigned long e;
    int ret = 0;

    if (!TEST_ptr(bio = BIO_new_mem_buf(truncated, sizeof(truncated))))
        goto err;
    ERR_clear_error();

    if (!TEST_int_lt(asn1_d2i_read_bio(bio, &buf), 0))
        goto err;
    e = ERR_peek_last_error();
    if (!TEST_int_eq(ERR_GET_LIB(e), ERR_LIB_ASN1)
        || !TEST_int_eq(ERR_GET_REASON(e), ASN1_R_NOT_ENOUGH_DATA))
        goto err;

    ret = 1;
err:
    BUF_MEM_free(buf);
    BIO_free(bio);
    return ret;
}

/*
 * An EOF reached while still inside an indefinite-length constructed value,
 * before its end-of-contents octets, is truncation too (not a clean boundary),
 * so it must also report ASN1_R_NOT_ENOUGH_DATA rather than an empty queue.
 */
static int test_d2i_read_bio_indefinite_truncated(void)
{
    /* SEQUENCE (indefinite) { INTEGER 0 } with the 00 00 EOC missing */
    static const unsigned char truncated_indefinite[] = {
        0x30, 0x80, /* SEQUENCE, indefinite length */
        0x02, 0x01, 0x00 /* INTEGER 0; no end-of-contents octets follow */
    };
    BIO *bio = NULL;
    BUF_MEM *buf = NULL;
    unsigned long e;
    int ret = 0;

    bio = BIO_new_mem_buf(truncated_indefinite, sizeof(truncated_indefinite));
    if (!TEST_ptr(bio))
        goto err;
    ERR_clear_error();

    if (!TEST_int_lt(asn1_d2i_read_bio(bio, &buf), 0))
        goto err;
    e = ERR_peek_last_error();
    if (!TEST_int_eq(ERR_GET_LIB(e), ERR_LIB_ASN1)
        || !TEST_int_eq(ERR_GET_REASON(e), ASN1_R_NOT_ENOUGH_DATA))
        goto err;

    ret = 1;
err:
    BUF_MEM_free(buf);
    BIO_free(bio);
    return ret;
}

/*
 * An EOF reached part-way through an object's header, with some header bytes
 * already buffered, is truncation as well.  This exercises the "diff != 0" arm
 * of the header-read check (distinct from the body read handled elsewhere).
 */
static int test_d2i_read_bio_partial_header(void)
{
    /* SEQUENCE with a 2-byte long-form length, but only one length byte given */
    static const unsigned char partial_header[] = {
        0x30, 0x82, 0x01 /* SEQUENCE, length declared as 2 bytes, 1 present */
    };
    BIO *bio = NULL;
    BUF_MEM *buf = NULL;
    unsigned long e;
    int ret = 0;

    if (!TEST_ptr(bio = BIO_new_mem_buf(partial_header, sizeof(partial_header))))
        goto err;
    ERR_clear_error();

    if (!TEST_int_lt(asn1_d2i_read_bio(bio, &buf), 0))
        goto err;
    e = ERR_peek_last_error();
    if (!TEST_int_eq(ERR_GET_LIB(e), ERR_LIB_ASN1)
        || !TEST_int_eq(ERR_GET_REASON(e), ASN1_R_NOT_ENOUGH_DATA))
        goto err;

    ret = 1;
err:
    BUF_MEM_free(buf);
    BIO_free(bio);
    return ret;
}

int setup_tests(void)
{
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_long);
#endif
    ADD_TEST(test_int32);
    ADD_TEST(test_uint32);
    ADD_TEST(test_int64);
    ADD_TEST(test_uint64);
    ADD_TEST(test_gentime);
    ADD_TEST(test_utctime);
    ADD_TEST(test_invalid_template);
    ADD_TEST(test_reuse_asn1_object);
    ADD_TEST(test_d2i_read_bio_clean_eof);
    ADD_TEST(test_d2i_read_bio_truncated);
    ADD_TEST(test_d2i_read_bio_indefinite_truncated);
    ADD_TEST(test_d2i_read_bio_partial_header);
    return 1;
}
