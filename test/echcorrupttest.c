/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/ech.h>
#include <internal/ech_helpers.h>

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
# define DEF_CERTS_DIR "test/certs"

/* the testcase numbers */
# define TESTCASE_CH 1
# define TESTCASE_SH 2
# define TESTCASE_RC 3

static OSSL_LIB_CTX *libctx = NULL;
static int verbose = 0;
static int testcase = 0;
static int testiter = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *echkeyfile = NULL;
static char *echconfig = NULL;
static size_t echconfiglen = 0;
static unsigned char *bin_echconfig;
static size_t bin_echconfiglen = 0;
static unsigned char *hpke_info = NULL;
static size_t hpke_infolen = 0;
static int short_test = 0;

/*
 * We can grab the CH and SH and manipulate those to check good
 * behaviour in the face of various errors. The most import thing
 * to test is the server processing of the new combinations that
 * result from the EncodedInnerClientHello (basically the raw
 * output of ECH decryption). We test that via test vectors for
 * those various borked values that we encrypt (via HPKE) and
 * inject into the CH. The SH is much simpler since there are
 * far fewer things to test with the magic encoding of the ECH
 * accept signal into the SH.random or HRR.extension, but we
 * can also test with borked versions of those.
 *
 * We'd like to, but so far cannot, do similarly for the ECH
 * retry-config in EncryptedExtensions. Seems like there's no
 * good way to get at the plaintext there and replace it with
 * a borked value. (QUIC tests seem to have a way to do that
 * but I've yet to figure how to replicate that here for the
 * retry-config.)
 */

/*
 * For client hello, we use a set of test vectors for each test:
 *  - encoded inner CH prefix
 *  - encoded inner CH for borking (esp. outer extensions)
 *  - encoded inner CH postfix
 *  - expected result (1 for good, 0 for bad)
 *  - expected error reason in the case of bad
 *
 * For each test, we replace the ECH ciphertext with a value
 * that's the HPKE seal/enc of an encoded inner-CH made up of
 * the three parts above and then see if we get the expected
 * error (reason).
 *
 * Whenever we re-seal we will get an error due to using the
 * wrong inner client random, which we don't know. But that
 * differs from errors in handling decoding after decryption.
 *
 * The inner CH is split in 3 variables so we can re-use pre
 * and post values, making it easier to understand/manipulate
 * a corrupted-or-not value.
 *
 * Note that the overall length of the encoded inner needs to
 * be mainained as otherwise outer length fields that are not
 * re-computed will be wrong. (We include a test of that as
 * well.) A radical change in the content of encoded inner
 * values (e.g. eliminating compression entirely) could break
 * these tests, but minor changes should have no effect due to
 * padding. (Such a radical change showing up as a fail of
 * these tests is arguably a good outcome.)
 */
typedef struct {
    const unsigned char *pre;
    size_t prelen;
    const unsigned char *forbork;
    size_t fblen;
    const unsigned char *post;
    size_t postlen;
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_ECHINNER;

/* a full padded, encoded inner client hello */
static const unsigned char entire_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* a full padded, encoded inner client hello with no extensions */
static const unsigned char no_ext_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* a too-short, encoded inner client hello */
static const unsigned char outer_short_encoded_inner[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01,
};

/* inner prefix up as far as outer_exts */
static const unsigned char encoded_inner_pre[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34
};

/* inner prefix with mad length of suites (0xDDDD) */
static const unsigned char badsuites_inner_pre[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0xDD, 0xDD, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x34
};

/* outer extensions - we play with variations of this */
static const unsigned char encoded_inner_outers[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outers with repetition of one extension (0x0B) */
static const unsigned char borked_outer1[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0B, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33
};

/* outers including a non-used extension (0xFFAB) */
static const unsigned char borked_outer2[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFF, 0xAB, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33
};

/* refer to SNI in outers! 2nd-last is 0x0000 */
static const unsigned char borked_outer3[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x33,
};

/* refer to ECH (0xfe0d) within outers */
static const unsigned char borked_outer4[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFE, 0x0D, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* refer to outers (0xfd00) within outers */
static const unsigned char borked_outer5[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0xFD, 0x00, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* no outers at all! include unknown ext 0xFF99 instead */
static const unsigned char borked_outer6[] = {
    0xFF, 0x99, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/*
 * outer with bad length (even number of octets)
 * we add a short bogus extension (0xFFFF) after
 * to ensure overall decode succeeds
 */
static const unsigned char borked_outer7[] = {
    0xfd, 0x00, 0x00, 0x0E, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0xFF, 0xFF, 0x00, 0x01, 0x00,
};

/* outer with bad inner length (odd number of octets)  */
static const unsigned char borked_outer8[] = {
    0xfd, 0x00, 0x00, 0x13, 0x11, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outer with HUGE length (0xFF13) */
static const unsigned char borked_outer9[] = {
    0xfd, 0x00, 0xFF, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* outer with zero length, followed by bogus ext */
static const unsigned char borked_outer10[] = {
    0xfd, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
    0x0F, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

static const unsigned char encoded_inner_post[] = {
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* muck up the padding by including non-zero stuff */
static const unsigned char bad_pad_encoded_inner_post[] = {
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* an encoded inner that's just too short */
static const unsigned char short_encoded_inner[] = {
    0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* A set of test vectors */
static TEST_ECHINNER test_inners[] = {
    /* 1. basic case - copy to show test code works with no change */
    { NULL, 0, NULL, 0, NULL, 0, 1, SSL_ERROR_NONE},

    /* 2. too-short encoded inner */
    { NULL, 0,
      outer_short_encoded_inner, sizeof(outer_short_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 3. otherwise-correct case that fails only due to client random */
    { NULL, 0,
      entire_encoded_inner, sizeof(entire_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 4. otherwise-correct case that fails only due to client random */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 5. fails HPKE decryption due to bad padding so treated as GREASE */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      bad_pad_encoded_inner_post, sizeof(bad_pad_encoded_inner_post),
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},

    /*
     * 6. unsupported extension instead of outers - resulting decoded
     * inner missing so much it seems to be the wrong protocol
     */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer6, sizeof(borked_outer6),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_UNSUPPORTED_PROTOCOL},

    /* 7. madly long ciphersuites in inner */
    { badsuites_inner_pre, sizeof(badsuites_inner_pre),
      encoded_inner_outers, sizeof(encoded_inner_outers),
      encoded_inner_post, sizeof(bad_pad_encoded_inner_post),
      0, /* expected result */
      SSL_R_TLSV1_ALERT_DECODE_ERROR},
    /* 8. so many padding bytes recovered clear is short */
    { NULL, 0,
      short_encoded_inner, sizeof(short_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_BAD_EXTENSION},

    /* 9. repeated codepoint inside outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer1, sizeof(borked_outer1),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 10. non-existent codepoint inside outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer2, sizeof(borked_outer2),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 11. include SNI in outers as well as both inner and outer */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer3, sizeof(borked_outer3),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 12. refer to ECH within outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer4, sizeof(borked_outer4),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 13. refer to outers within outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer5, sizeof(borked_outer5),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 14. bad length of outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer7, sizeof(borked_outer7),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 15. bad inner length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer8, sizeof(borked_outer8),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 16. HUGE length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer9, sizeof(borked_outer9),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 17. zero length in outers */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer10, sizeof(borked_outer10),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 18. case with no extensions at all */
    { NULL, 0,
      no_ext_encoded_inner, sizeof(no_ext_encoded_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_BAD_EXTENSION},

};

/*
 * For server hello/HRR, we use a set of test vectors for each test:
 *
 * - borkage encodes what we're breaking and is the OR
 *   of some #define'd OSSL_ECH_BORK_* flags
 * - bork is the value to use instead of the real one (or NULL)
 * - blen is the size of bork
 * - rv_expected is the return value expected for the connection
 * - err_expected is the reason code we expect to see
 */
typedef struct {
    int borkage; /* type of borkage */
    unsigned char *bork; /* borked value */
    size_t blen; /* len(bork) */
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_SH;

# define OSSL_ECH_BORK_NONE 0
# define OSSL_ECH_BORK_FLIP 1
# define OSSL_ECH_BORK_HRR (1 << 1)
# define OSSL_ECH_BORK_SHORT_HRR_CONFIRM (1 << 2)
# define OSSL_ECH_BORK_LONG_HRR_CONFIRM (1 << 3)
# define OSSL_ECH_BORK_GREASE (1 << 4)
# define OSSL_ECH_BORK_REPLACE (1 << 5)

/* a truncated ECH, with another bogus ext to match overall length */
static unsigned char shortech[] = {
    0xfe, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0xdd, 0xdd, 0x00, 0x00
};

/* a too-long ECH internal length */
static unsigned char longech[] = {
    0xfe, 0x0d, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
    0xdd, 0xdd, 0x00, 0x00
};

static TEST_SH test_shs[] = {
    /* 1. no messing about, should succeed */
    {OSSL_ECH_BORK_NONE, NULL, 0, 1, SSL_ERROR_NONE},
    /* 2. trigger HRR but no other borkage */
    {OSSL_ECH_BORK_HRR, NULL, 0, 1, SSL_ERROR_NONE},

    /* 3. GREASE and trigger HRR */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_GREASE,
     NULL, 0, 1, SSL_ERROR_NONE},

    /* 4. flip bits in SH.random ECH confirmation value */
    {OSSL_ECH_BORK_FLIP, NULL, 0, 0,
     SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 5. flip bits in HRR.exts ECH confirmation value */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_FLIP,
     NULL, 0, 0,
     SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 6. truncate HRR.exts ECH confirmation value */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_REPLACE,
     shortech, sizeof(shortech), 0,
     SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 7. too-long HRR.exts ECH confirmation value */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_REPLACE,
     longech, sizeof(longech), 0, SSL_R_ECH_REQUIRED},

};

/*
 * Test vectors for ECH raw decryption
 */
typedef struct {
    char *outer;
    size_t outerlen;
    unsigned char *ei;
    size_t eilen;
    int rv_expected;
    int dec_ok_expected;
    int err_expected;
    const unsigned char *exp_inner;
    size_t exp_innerlen;
} TEST_RAW;

/* inner1, encoded_inner1 and outer1 are a working, matching set */
static unsigned char inner1[] = {
    0x16, 0x03, 0x01, 0x01, 0x52,
    0x01, 0x00, 0x01, 0x4e, 0x03, 0x03, 0xae, 0x88,
    0x9b, 0xed, 0x7d, 0x15, 0x73, 0x7e, 0x7d, 0x10,
    0x38, 0x2b, 0xe8, 0x10, 0xb2, 0x64, 0x4f, 0xdb,
    0xff, 0x85, 0xab, 0x8c, 0x82, 0x8a, 0xd4, 0x3a,
    0xab, 0x38, 0xf8, 0xbf, 0xef, 0x23, 0x20, 0x0d,
    0x3d, 0xea, 0x02, 0x99, 0x8a, 0xaa, 0x5a, 0xec,
    0x12, 0xaa, 0x5f, 0xd1, 0x51, 0x7d, 0x14, 0xbe,
    0x23, 0x53, 0x80, 0x17, 0x98, 0x75, 0x2a, 0xd4,
    0x4a, 0xc9, 0x75, 0x25, 0x7b, 0x17, 0x94, 0x00,
    0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00,
    0xff, 0x01, 0x00, 0x00, 0xfd, 0x00, 0x0b, 0x00,
    0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x1d, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x24, 0x00,
    0x22, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x07, 0x08, 0x08, 0x08, 0x1a, 0x08, 0x1b, 0x08,
    0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
    0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02,
    0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    0x00, 0x33, 0x00, 0x67, 0x00, 0x65, 0x00, 0x18,
    0x00, 0x61, 0x04, 0x83, 0x84, 0x2c, 0xd5, 0x27,
    0x3a, 0x2f, 0x7f, 0xd8, 0x92, 0x21, 0xac, 0xa3,
    0x4f, 0x4b, 0xb0, 0xb9, 0x9a, 0x3a, 0x7e, 0x16,
    0x5d, 0xb3, 0xf0, 0x62, 0x7e, 0xfa, 0xf9, 0xc2,
    0x56, 0x4e, 0x1e, 0xa7, 0x48, 0xb4, 0x4c, 0xac,
    0x3b, 0xd6, 0xa1, 0x1f, 0xd2, 0x5f, 0x39, 0x77,
    0xbc, 0x58, 0x83, 0x54, 0xa2, 0xb4, 0xf1, 0x34,
    0xd6, 0x00, 0xbc, 0xf4, 0xe1, 0xfd, 0x1d, 0xbc,
    0xdf, 0x8d, 0xce, 0x76, 0xa2, 0x63, 0x8f, 0x2a,
    0x84, 0x9a, 0xfe, 0x3f, 0x59, 0x0d, 0x5e, 0x52,
    0x91, 0xe2, 0x1d, 0xc1, 0x5f, 0x6d, 0xff, 0xd5,
    0x90, 0x2b, 0xe5, 0x54, 0xe8, 0x4b, 0xae, 0xfc,
    0xbb, 0x63, 0xb8, 0x00, 0x00, 0x00, 0x1a, 0x00,
    0x18, 0x00, 0x00, 0x15, 0x63, 0x72, 0x79, 0x70,
    0x74, 0x6f, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64,
    0x66, 0x6c, 0x61, 0x72, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x10, 0x00, 0x18, 0x00, 0x16, 0x05,
    0x69, 0x6e, 0x6e, 0x65, 0x72, 0x06, 0x73, 0x65,
    0x63, 0x72, 0x65, 0x74, 0x08, 0x68, 0x74, 0x74,
    0x70, 0x2f, 0x31, 0x2e, 0x31, 0xfe, 0x0d, 0x00,
    0x01, 0x01
};

static unsigned char encoded_inner1[] = { /* incl. padding */
    0x03, 0x03, 0xae, 0x88, 0x9b, 0xed, 0x7d, 0x15,
    0x73, 0x7e, 0x7d, 0x10, 0x38, 0x2b, 0xe8, 0x10,
    0xb2, 0x64, 0x4f, 0xdb, 0xff, 0x85, 0xab, 0x8c,
    0x82, 0x8a, 0xd4, 0x3a, 0xab, 0x38, 0xf8, 0xbf,
    0xef, 0x23, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x56, 0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00,
    0x15, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
    0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61,
    0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x10,
    0x00, 0x18, 0x00, 0x16, 0x05, 0x69, 0x6e, 0x6e,
    0x65, 0x72, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65,
    0x74, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
    0x2e, 0x31, 0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static unsigned char outer1[] = {
    0x16, 0x03, 0x01, 0x02, 0x22,
    0x01, 0x00, 0x02, 0x1e, 0x03, 0x03, 0x54, 0x47,
    0x8c, 0x51, 0x1a, 0x8a, 0xae, 0x64, 0xd5, 0xf0,
    0x6b, 0xda, 0x46, 0x5c, 0x56, 0x76, 0x01, 0x69,
    0x68, 0xd0, 0xac, 0x0b, 0xd7, 0xb5, 0x4f, 0xcf,
    0x89, 0xb3, 0x3f, 0x6b, 0x70, 0x36, 0x20, 0x0d,
    0x3d, 0xea, 0x02, 0x99, 0x8a, 0xaa, 0x5a, 0xec,
    0x12, 0xaa, 0x5f, 0xd1, 0x51, 0x7d, 0x14, 0xbe,
    0x23, 0x53, 0x80, 0x17, 0x98, 0x75, 0x2a, 0xd4,
    0x4a, 0xc9, 0x75, 0x25, 0x7b, 0x17, 0x94, 0x00,
    0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00,
    0xff, 0x01, 0x00, 0x01, 0xcd, 0x00, 0x0b, 0x00,
    0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x1d, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x24, 0x00,
    0x22, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x07, 0x08, 0x08, 0x08, 0x1a, 0x08, 0x1b, 0x08,
    0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
    0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02,
    0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    0x00, 0x33, 0x00, 0x67, 0x00, 0x65, 0x00, 0x18,
    0x00, 0x61, 0x04, 0x83, 0x84, 0x2c, 0xd5, 0x27,
    0x3a, 0x2f, 0x7f, 0xd8, 0x92, 0x21, 0xac, 0xa3,
    0x4f, 0x4b, 0xb0, 0xb9, 0x9a, 0x3a, 0x7e, 0x16,
    0x5d, 0xb3, 0xf0, 0x62, 0x7e, 0xfa, 0xf9, 0xc2,
    0x56, 0x4e, 0x1e, 0xa7, 0x48, 0xb4, 0x4c, 0xac,
    0x3b, 0xd6, 0xa1, 0x1f, 0xd2, 0x5f, 0x39, 0x77,
    0xbc, 0x58, 0x83, 0x54, 0xa2, 0xb4, 0xf1, 0x34,
    0xd6, 0x00, 0xbc, 0xf4, 0xe1, 0xfd, 0x1d, 0xbc,
    0xdf, 0x8d, 0xce, 0x76, 0xa2, 0x63, 0x8f, 0x2a,
    0x84, 0x9a, 0xfe, 0x3f, 0x59, 0x0d, 0x5e, 0x52,
    0x91, 0xe2, 0x1d, 0xc1, 0x5f, 0x6d, 0xff, 0xd5,
    0x90, 0x2b, 0xe5, 0x54, 0xe8, 0x4b, 0xae, 0xfc,
    0xbb, 0x63, 0xb8, 0x00, 0x00, 0x00, 0x17, 0x00,
    0x15, 0x00, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75,
    0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65,
    0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x10,
    0x00, 0x12, 0x00, 0x10, 0x05, 0x6f, 0x75, 0x74,
    0x65, 0x72, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0x02, 0x68, 0x32, 0xfe, 0x0d, 0x00, 0xda,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xe7, 0x00, 0x20,
    0x17, 0x85, 0xdc, 0x0f, 0x28, 0x02, 0xa9, 0x08,
    0x01, 0x87, 0x02, 0xfa, 0x3b, 0x90, 0x60, 0xb3,
    0x11, 0xca, 0x2d, 0x0c, 0xeb, 0x7c, 0x7c, 0xd6,
    0x24, 0xee, 0x7c, 0xa4, 0xd7, 0x20, 0x22, 0x09,
    0x00, 0xb0, 0xd8, 0xf7, 0x75, 0xae, 0x9b, 0x77,
    0xbd, 0xb5, 0xda, 0xa6, 0x32, 0x8f, 0x27, 0x4b,
    0xec, 0xad, 0x4f, 0xef, 0xe6, 0x6c, 0xf7, 0xe6,
    0x23, 0x9d, 0x56, 0xfc, 0x98, 0x1c, 0x74, 0xe8,
    0xfe, 0xab, 0x0b, 0x93, 0x0a, 0x49, 0x8f, 0xb4,
    0x19, 0xfb, 0xed, 0x20, 0xe2, 0xb3, 0x9b, 0xab,
    0x49, 0x6e, 0x15, 0xa1, 0x9d, 0xe6, 0x46, 0x4f,
    0x9f, 0x24, 0x21, 0x96, 0xe5, 0xd5, 0x98, 0xd7,
    0xb5, 0x5c, 0x8e, 0x7f, 0x73, 0x17, 0xa2, 0xa1,
    0x09, 0x22, 0x24, 0x52, 0x38, 0x5c, 0xfd, 0x4d,
    0x6e, 0x55, 0x75, 0x2f, 0x57, 0x2c, 0xeb, 0x5a,
    0xc5, 0x68, 0x0e, 0x00, 0xd9, 0xc5, 0x9b, 0xe9,
    0xba, 0x16, 0xff, 0x32, 0x6d, 0xfd, 0x9a, 0xb4,
    0xc9, 0x4b, 0x19, 0x5c, 0x3b, 0x6f, 0xa8, 0x91,
    0x86, 0xb9, 0x48, 0xc7, 0x98, 0x85, 0x34, 0xaf,
    0x54, 0xd9, 0x98, 0xae, 0x95, 0x77, 0x6e, 0x4a,
    0xb6, 0xec, 0xf6, 0x6e, 0x14, 0x5b, 0x93, 0xfc,
    0x2c, 0x3d, 0x7c, 0x02, 0x52, 0xdd, 0x1b, 0xcb,
    0x42, 0xf5, 0x5c, 0xe3, 0x18, 0xfc, 0xcf, 0x92,
    0x00, 0x4b, 0xae, 0xaa, 0x9b, 0xea, 0x20, 0x66,
    0xbe, 0xf9, 0x1e, 0x68, 0x97, 0x92, 0x93, 0x0b,
    0x38, 0x98, 0x14, 0x55, 0x96, 0x20, 0x72, 0x97,
    0x03, 0xd4
};

/*
 * outer2 differs from outer1 only in the ECH config id,
 * which causes decryption to be treated as GREASE
 * we replace the 0xe7 value from outer1 with 0xFF
 */
static unsigned char outer2[] = {
    0x16, 0x03, 0x01, 0x02, 0x22,
    0x01, 0x00, 0x02, 0x1e, 0x03, 0x03, 0x54, 0x47,
    0x8c, 0x51, 0x1a, 0x8a, 0xae, 0x64, 0xd5, 0xf0,
    0x6b, 0xda, 0x46, 0x5c, 0x56, 0x76, 0x01, 0x69,
    0x68, 0xd0, 0xac, 0x0b, 0xd7, 0xb5, 0x4f, 0xcf,
    0x89, 0xb3, 0x3f, 0x6b, 0x70, 0x36, 0x20, 0x0d,
    0x3d, 0xea, 0x02, 0x99, 0x8a, 0xaa, 0x5a, 0xec,
    0x12, 0xaa, 0x5f, 0xd1, 0x51, 0x7d, 0x14, 0xbe,
    0x23, 0x53, 0x80, 0x17, 0x98, 0x75, 0x2a, 0xd4,
    0x4a, 0xc9, 0x75, 0x25, 0x7b, 0x17, 0x94, 0x00,
    0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00,
    0xff, 0x01, 0x00, 0x01, 0xcd, 0x00, 0x0b, 0x00,
    0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x1d, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x24, 0x00,
    0x22, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x07, 0x08, 0x08, 0x08, 0x1a, 0x08, 0x1b, 0x08,
    0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
    0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02,
    0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    0x00, 0x33, 0x00, 0x67, 0x00, 0x65, 0x00, 0x18,
    0x00, 0x61, 0x04, 0x83, 0x84, 0x2c, 0xd5, 0x27,
    0x3a, 0x2f, 0x7f, 0xd8, 0x92, 0x21, 0xac, 0xa3,
    0x4f, 0x4b, 0xb0, 0xb9, 0x9a, 0x3a, 0x7e, 0x16,
    0x5d, 0xb3, 0xf0, 0x62, 0x7e, 0xfa, 0xf9, 0xc2,
    0x56, 0x4e, 0x1e, 0xa7, 0x48, 0xb4, 0x4c, 0xac,
    0x3b, 0xd6, 0xa1, 0x1f, 0xd2, 0x5f, 0x39, 0x77,
    0xbc, 0x58, 0x83, 0x54, 0xa2, 0xb4, 0xf1, 0x34,
    0xd6, 0x00, 0xbc, 0xf4, 0xe1, 0xfd, 0x1d, 0xbc,
    0xdf, 0x8d, 0xce, 0x76, 0xa2, 0x63, 0x8f, 0x2a,
    0x84, 0x9a, 0xfe, 0x3f, 0x59, 0x0d, 0x5e, 0x52,
    0x91, 0xe2, 0x1d, 0xc1, 0x5f, 0x6d, 0xff, 0xd5,
    0x90, 0x2b, 0xe5, 0x54, 0xe8, 0x4b, 0xae, 0xfc,
    0xbb, 0x63, 0xb8, 0x00, 0x00, 0x00, 0x17, 0x00,
    0x15, 0x00, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75,
    0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65,
    0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x10,
    0x00, 0x12, 0x00, 0x10, 0x05, 0x6f, 0x75, 0x74,
    0x65, 0x72, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0x02, 0x68, 0x32, 0xfe, 0x0d, 0x00, 0xda,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x20,
    0x17, 0x85, 0xdc, 0x0f, 0x28, 0x02, 0xa9, 0x08,
    0x01, 0x87, 0x02, 0xfa, 0x3b, 0x90, 0x60, 0xb3,
    0x11, 0xca, 0x2d, 0x0c, 0xeb, 0x7c, 0x7c, 0xd6,
    0x24, 0xee, 0x7c, 0xa4, 0xd7, 0x20, 0x22, 0x09,
    0x00, 0xb0, 0xd8, 0xf7, 0x75, 0xae, 0x9b, 0x77,
    0xbd, 0xb5, 0xda, 0xa6, 0x32, 0x8f, 0x27, 0x4b,
    0xec, 0xad, 0x4f, 0xef, 0xe6, 0x6c, 0xf7, 0xe6,
    0x23, 0x9d, 0x56, 0xfc, 0x98, 0x1c, 0x74, 0xe8,
    0xfe, 0xab, 0x0b, 0x93, 0x0a, 0x49, 0x8f, 0xb4,
    0x19, 0xfb, 0xed, 0x20, 0xe2, 0xb3, 0x9b, 0xab,
    0x49, 0x6e, 0x15, 0xa1, 0x9d, 0xe6, 0x46, 0x4f,
    0x9f, 0x24, 0x21, 0x96, 0xe5, 0xd5, 0x98, 0xd7,
    0xb5, 0x5c, 0x8e, 0x7f, 0x73, 0x17, 0xa2, 0xa1,
    0x09, 0x22, 0x24, 0x52, 0x38, 0x5c, 0xfd, 0x4d,
    0x6e, 0x55, 0x75, 0x2f, 0x57, 0x2c, 0xeb, 0x5a,
    0xc5, 0x68, 0x0e, 0x00, 0xd9, 0xc5, 0x9b, 0xe9,
    0xba, 0x16, 0xff, 0x32, 0x6d, 0xfd, 0x9a, 0xb4,
    0xc9, 0x4b, 0x19, 0x5c, 0x3b, 0x6f, 0xa8, 0x91,
    0x86, 0xb9, 0x48, 0xc7, 0x98, 0x85, 0x34, 0xaf,
    0x54, 0xd9, 0x98, 0xae, 0x95, 0x77, 0x6e, 0x4a,
    0xb6, 0xec, 0xf6, 0x6e, 0x14, 0x5b, 0x93, 0xfc,
    0x2c, 0x3d, 0x7c, 0x02, 0x52, 0xdd, 0x1b, 0xcb,
    0x42, 0xf5, 0x5c, 0xe3, 0x18, 0xfc, 0xcf, 0x92,
    0x00, 0x4b, 0xae, 0xaa, 0x9b, 0xea, 0x20, 0x66,
    0xbe, 0xf9, 0x1e, 0x68, 0x97, 0x92, 0x93, 0x0b,
    0x38, 0x98, 0x14, 0x55, 0x96, 0x20, 0x72, 0x97,
    0x03, 0xd4
};

/*
 * outer3 is badly encoded, ECH length is wrong, being
 * 0xFF instead of 0xda
 */
static unsigned char outer3[] = {
    0x16, 0x03, 0x01, 0x02, 0x22,
    0x01, 0x00, 0x02, 0x1e, 0x03, 0x03, 0x54, 0x47,
    0x8c, 0x51, 0x1a, 0x8a, 0xae, 0x64, 0xd5, 0xf0,
    0x6b, 0xda, 0x46, 0x5c, 0x56, 0x76, 0x01, 0x69,
    0x68, 0xd0, 0xac, 0x0b, 0xd7, 0xb5, 0x4f, 0xcf,
    0x89, 0xb3, 0x3f, 0x6b, 0x70, 0x36, 0x20, 0x0d,
    0x3d, 0xea, 0x02, 0x99, 0x8a, 0xaa, 0x5a, 0xec,
    0x12, 0xaa, 0x5f, 0xd1, 0x51, 0x7d, 0x14, 0xbe,
    0x23, 0x53, 0x80, 0x17, 0x98, 0x75, 0x2a, 0xd4,
    0x4a, 0xc9, 0x75, 0x25, 0x7b, 0x17, 0x94, 0x00,
    0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00,
    0xff, 0x01, 0x00, 0x01, 0xcd, 0x00, 0x0b, 0x00,
    0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x1d, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x24, 0x00,
    0x22, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x07, 0x08, 0x08, 0x08, 0x1a, 0x08, 0x1b, 0x08,
    0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
    0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02,
    0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    0x00, 0x33, 0x00, 0x67, 0x00, 0x65, 0x00, 0x18,
    0x00, 0x61, 0x04, 0x83, 0x84, 0x2c, 0xd5, 0x27,
    0x3a, 0x2f, 0x7f, 0xd8, 0x92, 0x21, 0xac, 0xa3,
    0x4f, 0x4b, 0xb0, 0xb9, 0x9a, 0x3a, 0x7e, 0x16,
    0x5d, 0xb3, 0xf0, 0x62, 0x7e, 0xfa, 0xf9, 0xc2,
    0x56, 0x4e, 0x1e, 0xa7, 0x48, 0xb4, 0x4c, 0xac,
    0x3b, 0xd6, 0xa1, 0x1f, 0xd2, 0x5f, 0x39, 0x77,
    0xbc, 0x58, 0x83, 0x54, 0xa2, 0xb4, 0xf1, 0x34,
    0xd6, 0x00, 0xbc, 0xf4, 0xe1, 0xfd, 0x1d, 0xbc,
    0xdf, 0x8d, 0xce, 0x76, 0xa2, 0x63, 0x8f, 0x2a,
    0x84, 0x9a, 0xfe, 0x3f, 0x59, 0x0d, 0x5e, 0x52,
    0x91, 0xe2, 0x1d, 0xc1, 0x5f, 0x6d, 0xff, 0xd5,
    0x90, 0x2b, 0xe5, 0x54, 0xe8, 0x4b, 0xae, 0xfc,
    0xbb, 0x63, 0xb8, 0x00, 0x00, 0x00, 0x17, 0x00,
    0x15, 0x00, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75,
    0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65,
    0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x10,
    0x00, 0x12, 0x00, 0x10, 0x05, 0x6f, 0x75, 0x74,
    0x65, 0x72, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0x02, 0x68, 0x32, 0xfe, 0x0d, 0x00, 0xFF,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x20,
    0x17, 0x85, 0xdc, 0x0f, 0x28, 0x02, 0xa9, 0x08,
    0x01, 0x87, 0x02, 0xfa, 0x3b, 0x90, 0x60, 0xb3,
    0x11, 0xca, 0x2d, 0x0c, 0xeb, 0x7c, 0x7c, 0xd6,
    0x24, 0xee, 0x7c, 0xa4, 0xd7, 0x20, 0x22, 0x09,
    0x00, 0xb0, 0xd8, 0xf7, 0x75, 0xae, 0x9b, 0x77,
    0xbd, 0xb5, 0xda, 0xa6, 0x32, 0x8f, 0x27, 0x4b,
    0xec, 0xad, 0x4f, 0xef, 0xe6, 0x6c, 0xf7, 0xe6,
    0x23, 0x9d, 0x56, 0xfc, 0x98, 0x1c, 0x74, 0xe8,
    0xfe, 0xab, 0x0b, 0x93, 0x0a, 0x49, 0x8f, 0xb4,
    0x19, 0xfb, 0xed, 0x20, 0xe2, 0xb3, 0x9b, 0xab,
    0x49, 0x6e, 0x15, 0xa1, 0x9d, 0xe6, 0x46, 0x4f,
    0x9f, 0x24, 0x21, 0x96, 0xe5, 0xd5, 0x98, 0xd7,
    0xb5, 0x5c, 0x8e, 0x7f, 0x73, 0x17, 0xa2, 0xa1,
    0x09, 0x22, 0x24, 0x52, 0x38, 0x5c, 0xfd, 0x4d,
    0x6e, 0x55, 0x75, 0x2f, 0x57, 0x2c, 0xeb, 0x5a,
    0xc5, 0x68, 0x0e, 0x00, 0xd9, 0xc5, 0x9b, 0xe9,
    0xba, 0x16, 0xff, 0x32, 0x6d, 0xfd, 0x9a, 0xb4,
    0xc9, 0x4b, 0x19, 0x5c, 0x3b, 0x6f, 0xa8, 0x91,
    0x86, 0xb9, 0x48, 0xc7, 0x98, 0x85, 0x34, 0xaf,
    0x54, 0xd9, 0x98, 0xae, 0x95, 0x77, 0x6e, 0x4a,
    0xb6, 0xec, 0xf6, 0x6e, 0x14, 0x5b, 0x93, 0xfc,
    0x2c, 0x3d, 0x7c, 0x02, 0x52, 0xdd, 0x1b, 0xcb,
    0x42, 0xf5, 0x5c, 0xe3, 0x18, 0xfc, 0xcf, 0x92,
    0x00, 0x4b, 0xae, 0xaa, 0x9b, 0xea, 0x20, 0x66,
    0xbe, 0xf9, 0x1e, 0x68, 0x97, 0x92, 0x93, 0x0b,
    0x38, 0x98, 0x14, 0x55, 0x96, 0x20, 0x72, 0x97,
    0x03, 0xd4
};

/* struct: outer+len, encoded-inner+len, rv, dec_ok, err, inner+len */
static TEST_RAW raw_vectors[] = {

    /* 1. nominal operation */
    { (char *)outer1, sizeof(outer1), encoded_inner1, sizeof(encoded_inner1),
      1, 1, SSL_ERROR_NONE, inner1, sizeof(inner1)},
    /* 2. wrong config_id, treated as GREASE */
    { (char *)outer2, sizeof(outer2), encoded_inner1, sizeof(encoded_inner1),
      1, 0, SSL_ERROR_NONE, NULL, 0},
    /* 3. bad length of ECH in outer */
    { (char *)outer3, sizeof(outer3), encoded_inner1, sizeof(encoded_inner1),
      0, 0, ERR_R_PASSED_INVALID_ARGUMENT, NULL, 0}

};

/* Do a HPKE seal of a padded encoded inner */
static int seal_encoded_inner(char **out, int *outlen,
                              unsigned char *ei, size_t eilen,
                              const char *ch, int chlen,
                              size_t echoffset, size_t echlen)
{
    int res = 0;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *hctx = NULL;
    unsigned char *mypub = NULL;
    static size_t mypublen = 0;
    unsigned char *theirpub = NULL;
    size_t theirpublen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char *aad = NULL;
    size_t aadlen = 0;
    unsigned char *chout = NULL;
    size_t choutlen = 0;

    hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, hpke_suite,
                             OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (!TEST_ptr(hctx))
        goto err;
    mypublen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (!TEST_ptr(mypub = OPENSSL_malloc(mypublen)))
        goto err;
    theirpub = bin_echconfig + 11;
    theirpublen = 0x20;
    if (!TEST_true(OSSL_HPKE_encap(hctx, mypub, &mypublen,
                                   theirpub, theirpublen,
                                   hpke_info, hpke_infolen)))
        goto err;
    /* form up aad which is entire outer CH: zero's instead of ECH ciphertext */
    choutlen = chlen;
    if (!TEST_ptr(chout = OPENSSL_malloc(choutlen)))
        goto err;
    memcpy(chout, ch, chlen);
    memcpy(chout + echoffset + 12, mypub, mypublen);
    ct = chout + echoffset + 12 + mypublen + 2;
    ctlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, eilen);
    chout[echoffset + 12 + mypublen] = (ctlen >> 8) & 0xff;
    chout[echoffset + 12 + mypublen + 1] = ctlen & 0xff;
    /* the 9 skips the record layer header */
    aad = chout + SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH;
    aadlen = chlen - (SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH);
    if (short_test == 0 && ct + ctlen != aad + aadlen) {
        TEST_info("length oddity");
        goto err;
    }
    memset(ct, 0, ctlen);
    if (!TEST_true(OSSL_HPKE_seal(hctx, ct, &ctlen, aad, aadlen, ei, eilen)))
        goto err;
    *out = (char *)chout;
    *outlen = choutlen;
    res = 1;
err:
    OPENSSL_free(mypub);
    OSSL_HPKE_CTX_free(hctx);
    return res;

}

/* We'll either corrupt or copy the message based on the test index */
static int corrupt_or_copy(const char *msg, const int msglen,
                           char **msgout, int *msgoutlen)
{
    TEST_ECHINNER *ti = NULL;
    TEST_SH *ts = NULL;
    int is_ch = 0, is_sh = 0;
    unsigned char *encoded_inner = NULL;
    size_t prelen, fblen, postlen;
    size_t encoded_innerlen = 0;
    size_t sessid = 0, exts = 0, extlens = 0, echoffset = 0, echlen = 0;
    size_t snioffset = 0, snilen = 0;
    uint16_t echtype;
    int inner, rv = 0;

    /* is it a ClientHello or not? */
    if (testcase == TESTCASE_CH && msglen > 10 && msg[0] == SSL3_RT_HANDSHAKE
        && msg[5] == SSL3_MT_CLIENT_HELLO)
        is_ch = 1;
    /* is it a ServerHello or not? */
    if (testcase == TESTCASE_SH && msglen > 10 && msg[0] == SSL3_RT_HANDSHAKE
        && msg[5] == SSL3_MT_SERVER_HELLO)
        is_sh = 1;
    if (is_ch == 1) {
        if (testiter >= (int)OSSL_NELEM(test_inners))
            return 0;
        ti = &test_inners[testiter];
        prelen = ti->pre == NULL ? 0 : ti->prelen;
        fblen = ti->forbork == NULL ? 0 : ti->fblen;
        postlen = ti->post == NULL ? 0 : ti->postlen;
        /* check for editing errors */
        if (testiter != 0 && testiter != 1
            && prelen + fblen + postlen != sizeof(entire_encoded_inner)) {
            TEST_info("manual sizing error");
            return 0;
        }
        if (testiter == 1) /* the only case with a short ciphertext for now */
            short_test = 1;
        if (!TEST_true(ech_helper_get_ch_offsets((const unsigned char *)msg
                                                 + SSL3_RT_HEADER_LENGTH
                                                 + SSL3_HM_HEADER_LENGTH,
                                                 msglen
                                                 - SSL3_RT_HEADER_LENGTH
                                                 - SSL3_HM_HEADER_LENGTH,
                                                 &sessid, &exts, &extlens,
                                                 &echoffset, &echtype, &echlen,
                                                 &snioffset, &snilen, &inner)))
            return 0;
        /* that better be an outer ECH :-) */
        if (echoffset > 0 && !TEST_int_eq(inner, 0)) {
            TEST_info("better send outer");
            return 0;
        }
        /* bump offsets by 9 */
        echoffset += 9;
        snioffset += 9;
        /*
         * if it doesn't have an ECH, or if the forbork value in our test
         * array is NULL, just copy the entire input to output
         */
        if (echoffset == 9 || ti->forbork == NULL) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            *msgoutlen = msglen;
            return 1;
        }
        /* in this case, construct the encoded inner, then seal that */
        encoded_innerlen = prelen + fblen + postlen;
        if (!TEST_ptr(encoded_inner = OPENSSL_malloc(encoded_innerlen)))
            return 0;
        if (ti->pre != NULL) /* keep fuzz checker happy */
            memcpy(encoded_inner, ti->pre, prelen);
        if (ti->forbork != NULL)
            memcpy(encoded_inner + prelen, ti->forbork, fblen);
        if (ti->post != NULL)
            memcpy(encoded_inner + prelen + fblen, ti->post, postlen);
        if (!TEST_true(seal_encoded_inner(msgout, msgoutlen,
                                          encoded_inner, encoded_innerlen,
                                          msg, msglen, echoffset, echlen)))
            return 0;
        OPENSSL_free(encoded_inner);
        return 1;
    }
    if (is_sh == 1) {
        if (testiter >= (int)OSSL_NELEM(test_shs))
            return 0;
        ts = &test_shs[testiter];
        if (ts->borkage == 0) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            *msgoutlen = msglen;
            return 1;
        }
        /* flip bits in ECH confirmation */
        if (ts->borkage & OSSL_ECH_BORK_FLIP) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            if (ts->borkage & OSSL_ECH_BORK_HRR) {
                rv = ech_helper_get_sh_offsets((unsigned char *)msg + 9,
                                               msglen - 9,
                                               &exts, &echoffset, &echtype);
                if (!TEST_int_eq(rv, 1))
                    return 0;
                if (echoffset > 0) {
                    (*msgout)[9 + echoffset + 4] =
                        (*msgout)[9 + echoffset + 4] ^ 0xaa;
                }
            } else {
                (*msgout)[9 + 2 + SSL3_RANDOM_SIZE - 4] =
                    (*msgout)[9 + 2 + SSL3_RANDOM_SIZE - 4] ^ 0xaa;
            }
            *msgoutlen = msglen;
            return 1;
        }
        if (ts->borkage & OSSL_ECH_BORK_REPLACE &&
            ts->borkage & OSSL_ECH_BORK_HRR) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            rv = ech_helper_get_sh_offsets((unsigned char *)msg + 9,
                                           msglen - 9,
                                           &exts, &echoffset, &echtype);
            if (!TEST_int_eq(rv, 1))
                return 0;
            if (echoffset > 0) {
                memcpy(&((*msgout)[9 + echoffset]), ts->bork, ts->blen);
            }
            *msgoutlen = msglen;
            return 1;
        }
    }
    /* if doing nothing, do that... */
    if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
        return 0;
    *msgoutlen = msglen;
    return 1;
}

/*
 * return the bas64 encoded ECHConfigList from an ECH PEM file
 *
 * note - this isn't really needed as an offical API because
 * real clients will use DNS or scripting clients who need
 * this can do it easier with shell commands
 *
 * the caller should free the returned string
 */
static char *echconfiglist_from_PEM(const char *file)
{
    BIO *in = NULL;
    char *ecl_string = NULL;
    char lnbuf[OSSL_ECH_MAX_LINELEN];
    int readbytes = 0;

    if (!TEST_ptr(in = BIO_new(BIO_s_file()))
        || !TEST_int_ge(BIO_read_filename(in, file), 0))
        goto out;
    /* read 4 lines before the one we want */
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    ecl_string = OPENSSL_malloc(readbytes + 1);
    if (ecl_string == NULL)
        goto out;
    memcpy(ecl_string, lnbuf, readbytes);
    /* zap any '\n' or '\r' at the end if present */
    while (readbytes >= 0
           && (ecl_string[readbytes - 1] == '\n'
               || ecl_string[readbytes - 1] == '\r')) {
        ecl_string[readbytes - 1] = '\0';
        readbytes--;
    }
    if (readbytes == 0)
        goto out;
    BIO_free_all(in);
    return ecl_string;
out:
    BIO_free_all(in);
    return NULL;
}

static void copy_flags(BIO *bio)
{
    int flags;
    BIO *next = BIO_next(bio);

    flags = BIO_test_flags(next, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_set_flags(bio, flags);
}

/*
 * filter to corrupt or copy messages - this is basically copied
 * from the setup in test/sslcorrupttest.c
 */
static int tls_corrupt_write(BIO *bio, const char *in, int inl)
{
    int ret;
    BIO *next = BIO_next(bio);
    char *copy = NULL;
    int copylen = 0;

    ret = corrupt_or_copy(in, inl, &copy, &copylen);
    if (ret == 0)
        return 0;
    ret = BIO_write(next, copy, inl);
    OPENSSL_free(copy);
    copy_flags(bio);
    return ret;
}

/*
 * filter to do split-mode ECH front-end decrypt
 */
static int tls_split_mode(BIO *bio, const char *outer, int outerl)
{
    int ret = 0, ret2 = 0, is_ch = 0, dec_ok = 0, firstmsglen = 0;
    BIO *next = BIO_next(bio);
    size_t innerlen = 0;
    unsigned char *inner = NULL;
    char *inner_sni = NULL, *outer_sni = NULL;
    SSL_CTX *ctx = NULL;

    if (outerl > SSL3_RT_HEADER_LENGTH
        && outer[0] == SSL3_RT_HANDSHAKE
        && outer[5] == SSL3_MT_CLIENT_HELLO) {
        /*
         * len of 1st record layer message (incl. header) that may be
         * a CH, but that could be followed by early data
         */
        firstmsglen =
            SSL3_RT_HEADER_LENGTH
            + ((unsigned char)outer[3] << 8)
            + (unsigned char)outer[4];
        is_ch = 1;
        if (verbose) {
            TEST_info("outer CH len incl record layer is %d", outerl);
            TEST_info("first message is %d of that", firstmsglen);
        }
    }
    if (is_ch == 1) {
        ctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method());
        if (!TEST_true(SSL_CTX_ech_server_enable_file(ctx, echkeyfile,
                                                      SSL_ECH_USE_FOR_RETRY)))
            goto end;
        /* outer has to be longer than inner, so this is safe */
        inner = OPENSSL_malloc(outerl);
        if (inner == NULL)
            goto end;
        memset(inner, 0xAA, innerlen);
        innerlen = outerl;
        if (!TEST_true(SSL_CTX_ech_raw_decrypt(ctx, &dec_ok,
                                               &inner_sni, &outer_sni,
                                               (unsigned char *)outer, outerl,
                                               inner, &innerlen,
                                               NULL, NULL)))
            goto end;
        if (dec_ok == 1) {
            if (verbose)
                TEST_info("inner CH len incl record layer is %d",
                          (int)innerlen);
            ret = BIO_write(next, inner, (int)innerlen);
            OPENSSL_free(inner);
            OPENSSL_free(inner_sni);
            OPENSSL_free(outer_sni);
            SSL_CTX_free(ctx);
            if (firstmsglen < outerl) {
                ret2 = BIO_write(next, outer + firstmsglen,
                                 outerl - firstmsglen);
                if (verbose)
                    TEST_info("writing additional %d octets from after CH",
                              outerl - firstmsglen);
            } else {
                if (verbose)
                    TEST_info("nothing to write after inner");
            }
            if (verbose)
                TEST_info("returning %d from tls_split_mode filter",
                          ret + ret2);
            copy_flags(bio);
            /*
             * Weirdly, we need to return the original length of the
             * outer CH here or else the "unused" 182 octets turn up
             * as a badly encoded record layer message.
             * In the nominal test case right now, the original outer
             * CH length is 441, the inner CH length is 259 and the
             * 182 is the difference.
             * It took a surprising amount of trial-and-error to
             * figure that out, and I'm not sure it's really right,
             * but hey, it works, for now;-)
             */
            return outerl;
        }
        OPENSSL_free(inner);
        SSL_CTX_free(ctx);
    }
end:
    ret = BIO_write(next, outer, outerl);
    copy_flags(bio);
    return ret;
}

/*
 * This and others below are NOOP filters as we only mess
 * with things via the write filter method
 */
static int tls_noop_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio);

    ret = BIO_read(next, out, outl);
    copy_flags(bio);

    return ret;
}

static long tls_noop_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

static int tls_noop_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_noop_puts(BIO *bio, const char *str)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_noop_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int tls_noop_free(BIO *bio)
{
    BIO_set_init(bio, 0);

    return 1;
}

# define BIO_TYPE_CUSTOM_CORRUPT (0x80 | BIO_TYPE_FILTER)
# define BIO_TYPE_CUSTOM_SPLIT (0x81 | BIO_TYPE_FILTER)

static BIO_METHOD *method_tls_corrupt = NULL;
static BIO_METHOD *method_split_mode = NULL;

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_tls_corrupt_filter(void)
{
    if (method_tls_corrupt == NULL) {
        method_tls_corrupt = BIO_meth_new(BIO_TYPE_CUSTOM_CORRUPT,
                                          "TLS corrupt filter");
        if (method_tls_corrupt == NULL
            || !BIO_meth_set_write(method_tls_corrupt, tls_corrupt_write)
            || !BIO_meth_set_read(method_tls_corrupt, tls_noop_read)
            || !BIO_meth_set_puts(method_tls_corrupt, tls_noop_puts)
            || !BIO_meth_set_gets(method_tls_corrupt, tls_noop_gets)
            || !BIO_meth_set_ctrl(method_tls_corrupt, tls_noop_ctrl)
            || !BIO_meth_set_create(method_tls_corrupt, tls_noop_new)
            || !BIO_meth_set_destroy(method_tls_corrupt, tls_noop_free))
            return NULL;
    }
    return method_tls_corrupt;
}

static void bio_f_tls_corrupt_filter_free(void)
{
    BIO_meth_free(method_tls_corrupt);
}

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_tls_split_mode(void)
{
    if (method_split_mode == NULL) {
        method_split_mode = BIO_meth_new(BIO_TYPE_CUSTOM_SPLIT,
                                         "TLS ECH split-mode filter");
        if (method_split_mode == NULL
            || !BIO_meth_set_write(method_split_mode, tls_split_mode)
            || !BIO_meth_set_read(method_split_mode, tls_noop_read)
            || !BIO_meth_set_puts(method_split_mode, tls_noop_puts)
            || !BIO_meth_set_gets(method_split_mode, tls_noop_gets)
            || !BIO_meth_set_ctrl(method_split_mode, tls_noop_ctrl)
            || !BIO_meth_set_create(method_split_mode, tls_noop_new)
            || !BIO_meth_set_destroy(method_split_mode, tls_noop_free))
            return NULL;
    }
    return method_split_mode;
}

static void bio_f_tls_split_mode_free(void)
{
    BIO_meth_free(method_split_mode);
}

static int test_ch_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0, err = 0, connrv = 0, err_reason = 0;
    int exp_err = SSL_ERROR_NONE;
    TEST_ECHINNER *ti = NULL;

    testcase = TESTCASE_CH;
    testiter = testidx;
    ti = &test_inners[testidx];
    if (verbose)
        TEST_info("Starting #%d", testidx + 1);
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (ti->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, ti->rv_expected))
        goto end;
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != ti->err_expected);
    }
    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_sh_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *s_to_c_fbio;
    TEST_SH *ts = NULL;
    int testresult = 0, err = 0, connrv = 0, err_reason = 0;
    int exp_err = SSL_ERROR_NONE;
    unsigned char *retryconfig = NULL;
    size_t retryconfiglen = 0;

    testcase = TESTCASE_SH;
    testiter = testidx;
    ts = &test_shs[testidx];
    if (verbose)
        TEST_info("Starting #%d", testidx + 1);
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    if (ts->borkage & OSSL_ECH_BORK_GREASE) {
        if (!TEST_true(SSL_CTX_set_options(cctx, SSL_OP_ECH_GREASE)))
            goto end;
    } else {
        if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx,
                                                  (unsigned char *)echconfig,
                                                  echconfiglen)))
            goto end;
    }
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_ptr(s_to_c_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
                                      s_to_c_fbio, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    if (ts->borkage & OSSL_ECH_BORK_HRR
        && !TEST_true(SSL_set1_groups_list(server, "P-384")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (ts->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, ts->rv_expected))
        goto end;
    if (connrv == 1 && ts->borkage & OSSL_ECH_BORK_GREASE) {
        if (!TEST_true(SSL_ech_get_retry_config(client, &retryconfig,
                                                &retryconfiglen))
            || !TEST_ptr(retryconfig)
            || !TEST_int_ne(retryconfiglen, 0))
            goto end;
    }
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != ts->err_expected);
    }
    testresult = 1;
end:
    OPENSSL_free(retryconfig);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * We'll test the raw decrypt function here as it'll help to re-use
 * the HPKE enccryption and inner vars already defined here.
 */
static int ech_raw_dec(int idx)
{
    int res = 0, inner = 0, dec_ok = 0, rv = 0, err = 0, err_reason = 0;
    size_t sessid = 0, exts = 0, extlens = 0, echoffset = 0, echlen = 0;
    size_t snioffset = 0, snilen = 0, rec_innerlen = 0;
    unsigned char *rec_inner = NULL;
    uint16_t echtype;
    int choutlen;
    char *chout = NULL, *inner_sni = NULL, *outer_sni = NULL;
    SSL_CTX *sctx = NULL;
    TEST_RAW *tr = NULL;

    tr = &raw_vectors[idx];
    sctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method());
    if (!TEST_ptr(sctx))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    /* figure out offsets */
    rv = ech_helper_get_ch_offsets((const unsigned char *)tr->outer + 9,
                                   tr->outerlen - 9,
                                   &sessid, &exts, &extlens,
                                   &echoffset, &echtype, &echlen,
                                   &snioffset, &snilen, &inner);
    if (!TEST_int_eq(rv, 1))
        goto end;
    echoffset += 9;
    /* make a CH with a fresh ECH we can decrypt */
    if (!TEST_true(seal_encoded_inner(&chout, &choutlen,
                                      tr->ei, tr->eilen,
                                      tr->outer, tr->outerlen,
                                      echoffset, echlen)))
        goto end;
    if (!TEST_ptr((rec_inner = OPENSSL_malloc(choutlen))))
        goto end;
    rec_innerlen = choutlen;
    rv = SSL_CTX_ech_raw_decrypt(sctx, &dec_ok, &inner_sni, &outer_sni,
                                 (unsigned char *)chout, choutlen,
                                 rec_inner, &rec_innerlen,
                                 NULL, NULL);
    if (!TEST_int_eq(rv, tr->rv_expected))
        goto end;
    if (!TEST_int_eq(dec_ok, tr->dec_ok_expected))
        goto end;
    if (rv == 1 && dec_ok == 1) {
        if (!TEST_size_t_eq(rec_innerlen, tr->exp_innerlen))
            goto end;
        if (!TEST_mem_eq(rec_inner, rec_innerlen,
                         tr->exp_inner, tr->exp_innerlen))
            goto end;
    }
    if (rv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != tr->err_expected);
    }
    res = 1;
end:
    OPENSSL_free(inner_sni);
    OPENSSL_free(outer_sni);
    OPENSSL_free(rec_inner);
    OPENSSL_free(chout);
    SSL_CTX_free(sctx);
    return res;
}

/*
 * Split-mode test: Client sends to server but we use filters
 * to do a raw decrypt then re-inject the decrytped inner for
 * the server.
 */
static int ech_split_mode(int idx)
{
    int res = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    BIO *c_to_s_fbio = NULL;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_split_mode())))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_roundtrip_test: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_BACKEND))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_roundtrip_test: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH Corruption tests\n" },
        { NULL }
    };
    return test_options;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;
    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;
    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;
    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto err;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto err;
    echconfiglen = strlen(echconfig);
    bin_echconfiglen = ech_helper_base64_decode(echconfig, echconfiglen,
                                                &bin_echconfig);
    hpke_infolen = bin_echconfiglen + 200;
    if (!TEST_ptr(hpke_info = OPENSSL_malloc(hpke_infolen)))
        goto err;
    /* +/- 2 is to drop the ECHConfigList length at the start */
    if (!TEST_true(ech_helper_make_enc_info((unsigned char *)bin_echconfig + 2,
                                            bin_echconfiglen - 2,
                                            hpke_info, &hpke_infolen)))
        goto err;
    ADD_ALL_TESTS(test_ch_corrupt, OSSL_NELEM(test_inners));
    ADD_ALL_TESTS(test_sh_corrupt, OSSL_NELEM(test_shs));
    ADD_ALL_TESTS(ech_raw_dec, OSSL_NELEM(raw_vectors));
    ADD_ALL_TESTS(ech_split_mode, 1);
    return 1;
err:
    return 0;
#else
    return 1;
#endif
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    bio_f_tls_corrupt_filter_free();
    bio_f_tls_split_mode_free();
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    OPENSSL_free(bin_echconfig);
    OPENSSL_free(hpke_info);
#endif
}
