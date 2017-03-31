/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include "internal/asn1t.h"
#include "internal/numbers.h"
#include "test_main.h"
#include "testutil.h"

#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wunused-function"
# pragma GCC diagnostic ignored "-Wformat"
#endif
#ifdef __clang_
# pragma clang diagnostic ignored "-Wunused-function"
# pragma clang diagnostic ignored "-Wformat"
#endif

/***** Custom test data ******************************************************/

/*
 * We conduct tests with these arrays for every type we try out.
 * You will find the expected results together with the test structures
 * for each type, further down.
 */

static unsigned char t_true[] = {
    V_ASN1_BOOLEAN, 0x01, 0xff
};
static unsigned char t_zero[] = {
    V_ASN1_INTEGER, 0x01, 0x00
};
static unsigned char t_one[] = {
    V_ASN1_INTEGER, 0x01, 0x01
};
static unsigned char t_longundef[] = {
    V_ASN1_INTEGER, 0x04, 0x7f, 0xff, 0xff, 0xff
};
static unsigned char t_9bytes_1[] = {
    V_ASN1_INTEGER, 0x09, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static unsigned char t_8bytes_1[] = {
    V_ASN1_INTEGER, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char t_8bytes_2[] = {
    V_ASN1_INTEGER, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static unsigned char t_8bytes_3_pad[] = {
    V_ASN1_INTEGER, 0x09, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static unsigned char t_8bytes_4_neg[] = {
    V_ASN1_INTEGER, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char t_8bytes_5_negpad[] = {
    V_ASN1_INTEGER, 0x09, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* 32-bit long */
static unsigned char t_5bytes_1[] = {
    V_ASN1_INTEGER, 0x05, 0x01, 0xff, 0xff, 0xff, 0xff
};
static unsigned char t_4bytes_1[] = {
    V_ASN1_INTEGER, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00
};
/* We make the last byte 0xfe to avoid a clash with ASN1_LONG_UNDEF */
static unsigned char t_4bytes_2[] = {
    V_ASN1_INTEGER, 0x04, 0x7f, 0xff, 0xff, 0xfe
};
static unsigned char t_4bytes_3_pad[] = {
    V_ASN1_INTEGER, 0x05, 0x00, 0x7f, 0xff, 0xff, 0xfe
};
static unsigned char t_4bytes_4_neg[] = {
    V_ASN1_INTEGER, 0x04, 0x80, 0x00, 0x00, 0x00
};
static unsigned char t_4bytes_5_negpad[] = {
    V_ASN1_INTEGER, 0x05, 0xff, 0x80, 0x00, 0x00, 0x00
};

typedef struct {
    unsigned char *bytes1;
    size_t nbytes1;
    unsigned char *bytes2;
    size_t nbytes2;
} TEST_CUSTOM_DATA;
#define CUSTOM_DATA(v)                                   \
    { v, sizeof(v), t_one, sizeof(t_one) },       \
    { t_one, sizeof(t_one), v, sizeof(v) }

static TEST_CUSTOM_DATA test_custom_data[] = {
    CUSTOM_DATA(t_zero),
    CUSTOM_DATA(t_longundef),
    CUSTOM_DATA(t_one),
    CUSTOM_DATA(t_9bytes_1),
    CUSTOM_DATA(t_8bytes_1),
    CUSTOM_DATA(t_8bytes_2),
    CUSTOM_DATA(t_8bytes_3_pad),
    CUSTOM_DATA(t_8bytes_4_neg),
    CUSTOM_DATA(t_8bytes_5_negpad),
    CUSTOM_DATA(t_5bytes_1),
    CUSTOM_DATA(t_4bytes_1),
    CUSTOM_DATA(t_4bytes_2),
    CUSTOM_DATA(t_4bytes_3_pad),
    CUSTOM_DATA(t_4bytes_4_neg),
    CUSTOM_DATA(t_4bytes_5_negpad),
};


/***** Type specific test data ***********************************************/

/*
 * First, a few utility things that all type specific data can use, or in some
 * cases, MUST use.
 */

/*
 * For easy creation of arrays of expected data.  These macros correspond to
 * the uses of CUSTOM_DATA above.
 */
#define CUSTOM_EXPECTED_SUCCESS(num, znum) \
    { 0xff, num, 1 },                      \
    { 0xff, 1, znum }
#define CUSTOM_EXPECTED_FAILURE            \
    { 0, 0, 0 },                           \
    { 0, 0, 0 }

/*
 * A structure to collect all test information in.  There MUST be one instance
 * of this for each test
 */
typedef int i2d_fn(void **a, unsigned char **pp);
typedef void *d2i_fn(void **a, unsigned char **pp, long length);
typedef void ifree_fn(void *a);
typedef struct {
    char *name;

    /* An array of structures to compare decoded custom data with */
    void *encode_expectations;
    size_t encode_expectations_size;
    size_t encode_expectations_elem_size;

    /*
     * An array of structures that are encoded into a DER blob, which is
     * then decoded, and result gets compared with the original.
     */
    void *encdec_data;
    size_t encdec_data_size;
    size_t encdec_data_elem_size;

    /* The i2d function to use with this type */
    i2d_fn *i2d;
    /* The d2i function to use with this type */
    d2i_fn *d2i;
    /* Function to free a decoded structure */
    ifree_fn *ifree;
} TEST_PACKAGE;

/* To facilitate the creation of an encdec_data array */
#define ENCDEC_DATA(num, znum)                  \
    { 0xff, num, 1 }, { 0xff, 1, znum }
#define ENCDEC_ARRAY(max, zmax)                 \
    ENCDEC_DATA(max,zmax),                      \
    ENCDEC_DATA(1, 1),                          \
    ENCDEC_DATA(-1, -1),                        \
    ENCDEC_DATA(0, ASN1_LONG_UNDEF)

/***** LONG ******************************************************************/

typedef struct {
    /* If decoding is expected to succeed, set this to 1, otherwise 0 */
    ASN1_BOOLEAN success;
    long test_long;
    long test_zlong;
} ASN1_LONG_DATA;

ASN1_SEQUENCE(ASN1_LONG_DATA) = {
    ASN1_SIMPLE(ASN1_LONG_DATA, success, ASN1_FBOOLEAN),
    ASN1_SIMPLE(ASN1_LONG_DATA, test_long, LONG),
    ASN1_SIMPLE(ASN1_LONG_DATA, test_zlong, ZLONG)
} static_ASN1_SEQUENCE_END(ASN1_LONG_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_LONG_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_LONG_DATA)

static ASN1_LONG_DATA long_expected[] = {
    /* The following should fail on the second because it's the default */
    { 0xff, 0, 1 }, { 0, 0, 0 }, /* t_zero */
    { 0, 0, 0 }, { 0xff, 1, 0x7fffffff }, /* t_longundef */
    CUSTOM_EXPECTED_SUCCESS(1, 1), /* t_one */
    CUSTOM_EXPECTED_FAILURE,     /* t_9bytes_1 */
#ifdef SIXTY_FOUR_BIT_LONG
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(LONG_MAX, LONG_MAX), /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(LONG_MIN, LONG_MIN), /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(0x1ffffffff, 0x1ffffffff), /* t_5bytes_1 */
#else
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad */
    CUSTOM_EXPECTED_FAILURE,     /* t_5bytes_1 */
#endif
    /*
     * Note: because t_4bytes_1 doesn't have a negative indication, we need
     * to code the expectation with explicit constants which are negative on
     * 32-bit platforms and positive on larger ones.
     */
    CUSTOM_EXPECTED_SUCCESS(0x80000000, 0x80000000), /* t_4bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT32_MAX - 1, INT32_MAX -1), /* t_4bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(INT32_MIN, INT32_MIN), /* t_4bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_5_negpad (illegal padding) */
};
static ASN1_LONG_DATA long_encdec_data[] = {
    ENCDEC_ARRAY(LONG_MAX - 1, LONG_MAX),
    /* Check that default numbers fail */
    { 0, ASN1_LONG_UNDEF, 1 }, { 0, 1, 0 }
};

static TEST_PACKAGE long_test_package = {
    "LONG",
    long_expected, sizeof(long_expected), sizeof(long_expected[0]),
    long_encdec_data, sizeof(long_encdec_data), sizeof(long_encdec_data[0]),
    (i2d_fn *)i2d_ASN1_LONG_DATA, (d2i_fn *)d2i_ASN1_LONG_DATA,
    (ifree_fn *)ASN1_LONG_DATA_free
};

/***** INT32 *****************************************************************/

typedef struct {
    ASN1_BOOLEAN success;
    int32_t test_int32;
    int32_t test_zint32;
} ASN1_INT32_DATA;

ASN1_SEQUENCE(ASN1_INT32_DATA) = {
    ASN1_SIMPLE(ASN1_LONG_DATA, success, ASN1_FBOOLEAN),
    ASN1_SIMPLE(ASN1_INT32_DATA, test_int32, INT32),
    ASN1_SIMPLE(ASN1_INT32_DATA, test_zint32, ZINT32)
} static_ASN1_SEQUENCE_END(ASN1_INT32_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_INT32_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_INT32_DATA)

static ASN1_INT32_DATA int32_expected[] = {
    CUSTOM_EXPECTED_SUCCESS(0, 0), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(ASN1_LONG_UNDEF, ASN1_LONG_UNDEF), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(1, 1), /* t_one */
    CUSTOM_EXPECTED_FAILURE,     /* t_9bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad */
    CUSTOM_EXPECTED_FAILURE,     /* t_5bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_1 (too large positive) */
    CUSTOM_EXPECTED_SUCCESS(INT32_MAX - 1, INT32_MAX -1), /* t_4bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(INT32_MIN, INT32_MIN), /* t_4bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_5_negpad (illegal padding) */
};
static ASN1_INT32_DATA int32_encdec_data[] = {
    ENCDEC_ARRAY(INT32_MAX, INT32_MAX),
};

static TEST_PACKAGE int32_test_package = {
    "INT32",
    int32_expected, sizeof(int32_expected), sizeof(int32_expected[0]),
    int32_encdec_data, sizeof(int32_encdec_data), sizeof(int32_encdec_data[0]),
    (i2d_fn *)i2d_ASN1_INT32_DATA, (d2i_fn *)d2i_ASN1_INT32_DATA,
    (ifree_fn *)ASN1_INT32_DATA_free
};

/***** UINT32 ****************************************************************/

typedef struct {
    ASN1_BOOLEAN success;
    uint32_t test_uint32;
    uint32_t test_zuint32;
} ASN1_UINT32_DATA;

ASN1_SEQUENCE(ASN1_UINT32_DATA) = {
    ASN1_SIMPLE(ASN1_LONG_DATA, success, ASN1_FBOOLEAN),
    ASN1_SIMPLE(ASN1_UINT32_DATA, test_uint32, UINT32),
    ASN1_SIMPLE(ASN1_UINT32_DATA, test_zuint32, ZUINT32)
} static_ASN1_SEQUENCE_END(ASN1_UINT32_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_UINT32_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_UINT32_DATA)

static ASN1_UINT32_DATA uint32_expected[] = {
    CUSTOM_EXPECTED_SUCCESS(0, 0), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(ASN1_LONG_UNDEF, ASN1_LONG_UNDEF), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(1, 1), /* t_one */
    CUSTOM_EXPECTED_FAILURE,     /* t_9bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_1 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad */
    CUSTOM_EXPECTED_FAILURE,     /* t_5bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(0x80000000, 0x80000000), /* t_4bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT32_MAX - 1, INT32_MAX -1), /* t_4bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_4_neg (illegal negative value) */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_5_negpad (illegal padding) */
};
static ASN1_UINT32_DATA uint32_encdec_data[] = {
    ENCDEC_ARRAY(UINT32_MAX, UINT32_MAX),
};

static TEST_PACKAGE uint32_test_package = {
    "UINT32",
    uint32_expected, sizeof(uint32_expected), sizeof(uint32_expected[0]),
    uint32_encdec_data, sizeof(uint32_encdec_data), sizeof(uint32_encdec_data[0]),
    (i2d_fn *)i2d_ASN1_UINT32_DATA, (d2i_fn *)d2i_ASN1_UINT32_DATA,
    (ifree_fn *)ASN1_UINT32_DATA_free
};

/***** INT64 *****************************************************************/

typedef struct {
    ASN1_BOOLEAN success;
    int64_t test_int64;
    int64_t test_zint64;
} ASN1_INT64_DATA;

ASN1_SEQUENCE(ASN1_INT64_DATA) = {
    ASN1_SIMPLE(ASN1_LONG_DATA, success, ASN1_FBOOLEAN),
    ASN1_SIMPLE(ASN1_INT64_DATA, test_int64, INT64),
    ASN1_SIMPLE(ASN1_INT64_DATA, test_zint64, ZINT64)
} static_ASN1_SEQUENCE_END(ASN1_INT64_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_INT64_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_INT64_DATA)

static ASN1_INT64_DATA int64_expected[] = {
    CUSTOM_EXPECTED_SUCCESS(0, 0), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(ASN1_LONG_UNDEF, ASN1_LONG_UNDEF), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(1, 1), /* t_one */
    CUSTOM_EXPECTED_FAILURE,     /* t_9bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT64_MIN, INT64_MIN), /* t_8bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT64_MAX, INT64_MAX), /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(INT64_MIN, INT64_MIN), /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(0x1ffffffff, 0x1ffffffff), /* t_5bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(0x80000000, 0x80000000), /* t_4bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT32_MAX - 1, INT32_MAX -1), /* t_4bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_SUCCESS(0x80000000, 0x80000000), /* t_4bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_5_negpad (illegal padding) */
};
static ASN1_INT64_DATA int64_encdec_data[] = {
    ENCDEC_ARRAY(INT64_MAX, INT64_MAX),
    ENCDEC_ARRAY(INT32_MAX, INT32_MAX),
};

static TEST_PACKAGE int64_test_package = {
    "INT64",
    int64_expected, sizeof(int64_expected), sizeof(int64_expected[0]),
    int64_encdec_data, sizeof(int64_encdec_data), sizeof(int64_encdec_data[0]),
    (i2d_fn *)i2d_ASN1_INT64_DATA, (d2i_fn *)d2i_ASN1_INT64_DATA,
    (ifree_fn *)ASN1_INT64_DATA_free
};

/***** UINT64 ****************************************************************/

typedef struct {
    ASN1_BOOLEAN success;
    uint64_t test_uint64;
    uint64_t test_zuint64;
} ASN1_UINT64_DATA;

ASN1_SEQUENCE(ASN1_UINT64_DATA) = {
    ASN1_SIMPLE(ASN1_LONG_DATA, success, ASN1_FBOOLEAN),
    ASN1_SIMPLE(ASN1_UINT64_DATA, test_uint64, UINT64),
    ASN1_SIMPLE(ASN1_UINT64_DATA, test_zuint64, ZUINT64)
} static_ASN1_SEQUENCE_END(ASN1_UINT64_DATA)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_UINT64_DATA)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(ASN1_UINT64_DATA)

static ASN1_UINT64_DATA uint64_expected[] = {
    CUSTOM_EXPECTED_SUCCESS(0, 0), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(ASN1_LONG_UNDEF, ASN1_LONG_UNDEF), /* t_zero */
    CUSTOM_EXPECTED_SUCCESS(1, 1), /* t_one */
    CUSTOM_EXPECTED_FAILURE,     /* t_9bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT64_MIN, INT64_MIN), /* t_8bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT64_MAX, INT64_MAX), /* t_8bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_3_pad */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_4_neg */
    CUSTOM_EXPECTED_FAILURE,     /* t_8bytes_5_negpad */
    CUSTOM_EXPECTED_SUCCESS(0x1ffffffff, 0x1ffffffff), /* t_5bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(0x80000000, 0x80000000), /* t_4bytes_1 */
    CUSTOM_EXPECTED_SUCCESS(INT32_MAX - 1, INT32_MAX -1), /* t_4bytes_2 */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_3_pad (illegal padding) */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_4_neg (illegal negative value) */
    CUSTOM_EXPECTED_FAILURE,     /* t_4bytes_5_negpad (illegal padding) */
};
static ASN1_UINT64_DATA uint64_encdec_data[] = {
    ENCDEC_ARRAY(UINT64_MAX, UINT64_MAX),
};

static TEST_PACKAGE uint64_test_package = {
    "UINT64",
    uint64_expected, sizeof(uint64_expected), sizeof(uint64_expected[0]),
    uint64_encdec_data, sizeof(uint64_encdec_data), sizeof(uint64_encdec_data[0]),
    (i2d_fn *)i2d_ASN1_UINT64_DATA, (d2i_fn *)d2i_ASN1_UINT64_DATA,
    (ifree_fn *)ASN1_UINT64_DATA_free
};

/***** General testing functions *********************************************/


/* Template structure to map onto any test data structure */
typedef struct {
    ASN1_BOOLEAN success;
    unsigned char bytes[1];       /* In reality, there's more */
} EXPECTED;

/*
 * do_decode returns a tristate:
 *
 *      -1      Couldn't decode
 *      0       decoded structure wasn't what was expected (failure)
 *      1       decoded structure was what was expected (success)
 */
static int do_decode(unsigned char *bytes, long nbytes,
                     const EXPECTED *expected, size_t expected_size,
                     const TEST_PACKAGE *package)
{
    EXPECTED *enctst = NULL;
    const unsigned char *start;
    int ret = 0;

    start = bytes;
    enctst = package->d2i(NULL, &bytes, nbytes);
    if (enctst == NULL) {
        if (expected->success == 0) {
            ret = 1;
            ERR_clear_error();
        } else {
            ret = -1;
        }
    } else {
        if (start + nbytes == bytes
            && memcmp(enctst, expected, expected_size) == 0)
            ret = 1;
        else
            ret = 0;
    }

    package->ifree(enctst);
    return ret;
}

/* Do an encode/decode round trip */
static int do_enc_dec(EXPECTED *bytes, long nbytes,
                      const TEST_PACKAGE *package)
{
    unsigned char *data = NULL;
    int len;
    int ret = 0;
    void *p = bytes;

    len = package->i2d(p, &data);
    if (len < 0)
        return -1;

    ret = do_decode(data, len, bytes, nbytes, package);
    OPENSSL_free(data);
    return ret;
}

/* Attempt to decode a custom encoding of the test structure */
static int do_decode_custom(const TEST_CUSTOM_DATA *custom_data,
                            const EXPECTED *expected, size_t expected_size,
                            const TEST_PACKAGE *package)
{
    size_t lenbytes, fulllen;
    size_t totlen = sizeof(t_true) + custom_data->nbytes1
        + custom_data->nbytes2;
    unsigned char *encoding, *p = NULL;
    int ret;

    /* lenbytes doesn't include the initial "short form" length byte */
    if (totlen > 255)
        lenbytes = 2;
    else if (totlen > 127)
        lenbytes = 1;
    else
        lenbytes = 0;

    /* We have 2 bytes for the sequence tag, and the first length byte */
    fulllen = 2 + lenbytes + totlen;
    encoding = p = OPENSSL_malloc(fulllen);
    if (encoding == NULL)
        return -1;

    /* Sequence tag */
    *p++ = 0x30;
    if (lenbytes == 0) {
        *p++ = totlen;
    } else {
        *p++ = lenbytes;
        if (lenbytes == 2) {
            *p++ = 0x80 | (totlen >> 8);
            totlen &= 0xff;
            *p++ = totlen;
        } else {
            *p++ = 0x80 | totlen;
        }
    }
    memcpy(p, t_true, sizeof(t_true)); /* Marks decoding success */
    p += sizeof(t_true);
    memcpy(p, custom_data->bytes1, custom_data->nbytes1);
    p += custom_data->nbytes1;
    memcpy(p, custom_data->bytes2, custom_data->nbytes2);
    p += custom_data->nbytes2;

    ret = do_decode(encoding, fulllen, expected, expected_size, package);
    OPENSSL_free(encoding);

    return ret;
}


static int test_intern(const TEST_PACKAGE *package)
{
    unsigned int i;
    size_t nelems;
    int fail = 0;

    /* Do decode_custom checks */
    nelems = package->encode_expectations_size
        / package->encode_expectations_elem_size;
    OPENSSL_assert(nelems ==
                   sizeof(test_custom_data) / sizeof(test_custom_data[0]));
    for (i = 0; i < nelems; i++) {
        size_t pos = i * package->encode_expectations_elem_size;
        switch (do_decode_custom(&test_custom_data[i],
                                 (EXPECTED *)&((unsigned char *)package
                                               ->encode_expectations)[pos],
                                 package->encode_expectations_elem_size,
                                 package)) {
        case -1:
            fprintf(stderr, "Failed custom decode round trip %u of %s\n",
                    i, package->name);
            ERR_print_errors_fp(stderr);
            fail++;
            ERR_clear_error();
            break;
        case 0:
            fprintf(stderr, "Custom decode round trip %u of %s mismatch\n",
                    i, package->name);
            fail++;
            break;
        case 1:
            break;
        default:
            OPENSSL_die("do_enc_dec() return unknown value",
                        __FILE__, __LINE__);
        }
    }

    /* Do enc_dec checks */
    nelems = package->encdec_data_size / package->encdec_data_elem_size;
    for (i = 0; i < nelems; i++) {
        size_t pos = i * package->encdec_data_elem_size;
        switch (do_enc_dec((EXPECTED *)&((unsigned char *)package
                                         ->encdec_data)[pos],
                           package->encdec_data_elem_size,
                           package)) {
        case -1:
            fprintf(stderr, "Failed encode/decode round trip %u of %s\n",
                    i, package->name);
            ERR_print_errors_fp(stderr);
            ERR_clear_error();
            fail++;
            break;
        case 0:
            fprintf(stderr, "Encode/decode round trip %u of %s mismatch\n",
                    i, package->name);
            fail++;
            break;
        case 1:
            break;
        default:
            OPENSSL_die("do_enc_dec() return unknown value",
                        __FILE__, __LINE__);
        }
    }

    return fail == 0;
}

static int test_long(void)
{
    return test_intern(&long_test_package);
}

static int test_int32(void)
{
    return test_intern(&int32_test_package);
}

static int test_uint32(void)
{
    return test_intern(&uint32_test_package);
}

static int test_int64(void)
{
    return test_intern(&int64_test_package);
}

static int test_uint64(void)
{
    return test_intern(&uint64_test_package);
}

void register_tests(void)
{
    ADD_TEST(test_long);
    ADD_TEST(test_int32);
    ADD_TEST(test_uint32);
    ADD_TEST(test_int64);
    ADD_TEST(test_uint64);
}
