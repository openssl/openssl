/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
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
#include <internal/packet.h>

#define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
#define DEF_CERTS_DIR "test/certs"

/* the testcase numbers */
#define TESTCASE_CH 1
#define TESTCASE_SH 2
#define TESTCASE_ECH 3

static OSSL_LIB_CTX *libctx = NULL;
static char *propq = NULL;
static OSSL_ECHSTORE *es = NULL;
static OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
static int verbose = 0;
static int testcase = 0;
static int testiter = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static unsigned char *hpke_info = NULL;
static size_t hpke_infolen = 0;
static int short_test = 0;

/*
 * An x25519 ech key and ECHConfigList with public name example.com
 * and the associated base64 encoded and binary forms of that
 * ECHConfigList - hardcoding here is ok as we're testing for
 * effects of corrupted CH/SH and not for ECHConfig badness.
 */
static const char pem_kp1[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEILDIeo9Eqc4K9/uQ0PNAyMaP60qrxiSHT2tNZL3ksIZS\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";
static const char echconfig[] =
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA"
    "AQALZXhhbXBsZS5jb20AAA==";
static size_t echconfiglen = sizeof(echconfig) - 1;
static unsigned char bin_echconfig[] =
    {
        0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0x6c, 0x00,
        0x20, 0x00, 0x20, 0x98, 0xec, 0x1d, 0x1f, 0xff,
        0x72, 0xaf, 0x1c, 0x81, 0x5d, 0xa2, 0xa1, 0x5a,
        0x39, 0xb7, 0x54, 0xf1, 0x86, 0x14, 0xf8, 0xc7,
        0x41, 0x7f, 0x8b, 0xf3, 0x6c, 0xb8, 0x40, 0x00,
        0xbd, 0x90, 0x0b, 0x00, 0x04, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
        0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
    };
static size_t bin_echconfiglen = sizeof(bin_echconfig);

/*
 * We can grab the CH and SH and manipulate those to check good
 * behaviour in the face of various errors. The most important
 * thing to test is the server processing of the new combinations
 * that result from the EncodedInnerClientHello (basically the raw
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

/* refer to key-share 0x00 0x33 (51) twice within outers */
static const unsigned char borked_outer11[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x33, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
};

/* refer to psk kex mode (0x00 0x2D/45) within outers */
static const unsigned char borked_outer12[] = {
    0xfd, 0x00, 0x00, 0x13, 0x12, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x2D, 0x00, 0x2b, 0x00, 0x2d, 0x00, 0x33,
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

/*
 * too many outer extensions - max is 20 (decimal)
 * defined as OSSL_ECH_OUTERS_MAX
 */
static const unsigned char too_many_outers[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00,
    0x00, 0x4c, /* extslen, incl. our added outers */
    0xfd, 0x00, /* outers */
    0x00, 0x2b, /* len of outers */
    0x2a, /* above minus one (42) 21 outers */
    0x00, 0x0b, /* the 9 'normal' outers */
    0x00, 0x0a,
    0x00, 0x23,
    0x00, 0x16,
    0x00, 0x17,
    0x00, 0x0d,
    0x00, 0x2b,
    0x00, 0x2d,
    0x00, 0x33,
    /* 12 more outers, set 'em all to ALPN (16, 0x10) */
    0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10,
    0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10,
    0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10,
    /* and now the inner SNI, inner ECH and 3 padding octets */
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x00,
};

/*
 * a full padded, encoded inner client hello, but
 * without an inner supported extensions, (take
 * out the 0x00 0x2b and add some padding zeros,
 * adjusting lengths) and hence meaning TLSv1.2
 */
static const unsigned char no_supported_exts[] = {
    0x03, 0x03, 0x7b, 0xe8, 0xc1, 0x18, 0xd7, 0xd1,
    0x9c, 0x39, 0xa4, 0xfa, 0xce, 0x75, 0x72, 0x40,
    0xcf, 0x37, 0xbb, 0x4c, 0xcd, 0xa7, 0x62, 0xda,
    0x04, 0xd2, 0xdb, 0xe2, 0x89, 0x33, 0x36, 0x15,
    0x96, 0xc9, 0x00, 0x00, 0x08, 0x13, 0x02, 0x13,
    0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
    0x32, 0xfd, 0x00, 0x00, 0x11, 0x10, 0x00, 0x0b,
    0x00, 0x0a, 0x00, 0x23, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x0d, 0x00, 0x2d, 0x00, 0x33,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

static const unsigned char tlsv12_inner[] = {
    0x03, 0x03, /* version, then client-random */
    0x23, 0xc3, 0xa0, 0x49, 0xea, 0x17, 0x9e, 0x30,
    0x6f, 0x0e, 0xc9, 0x79, 0xd0, 0xd1, 0xfd, 0xea,
    0x63, 0xfd, 0x20, 0x04, 0xaa, 0xb3, 0x2a, 0x29,
    0xf5, 0x96, 0x60, 0x29, 0x42, 0x7e, 0x5c, 0x7b,
    0x00, /* zero'd session ID */
    0x00, 0x02, /* ciphersuite len, just one */
    0xc0, 0x2c, /* a TLSv1.2 ciphersuite */
    0x01, 0x00, /* no compression */
    0x00, 0x32, /* extslen */
    0xfd, 0x00, /* outers */
    0x00, 0x11, /* len of outers */
    0x10, /* above minus one (16) 8 outers */
    0x00, 0x0b, /* the 'normal' outers, minus supported_versions */
    0x00, 0x0a,
    0x00, 0x23,
    0x00, 0x16,
    0x00, 0x17,
    0x00, 0x0d,
    0x00, 0x2d,
    0x00, 0x33,
    /* and now the inner SNI, inner ECH and padding octets */
    0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
    0x0f, 0x66, 0x6f, 0x6f, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    0xfe, 0x0d, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
      0, /* expected result - error is different with -notls1_2 */
#ifdef OPENSSL_NO_TLS1_2
      SSL_R_VERSION_TOO_LOW
#else
      SSL_R_UNSUPPORTED_PROTOCOL
#endif
    },

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
    /*
     * 19. include key-share twice in outers as well as both inner and outer.
     * There was a change with this one recently that can/does cause a
     * different error message (used to be SSL_R_BAD_EXTENSION, but now
     * mostly ERR_R_INTERNAL_ERROR). The issue is that this test repeats the
     * key_share in the compresed exts and with PQ kybrid KEMs those are
     * so large that instead of detecting the duplicate extension we see
     * an earlier error where the inner CH is bigger than the outer.
     */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer11, sizeof(borked_outer11),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
#ifdef OPENSSL_NO_ML_KEM
      SSL_R_BAD_EXTENSION
#else
      ERR_R_INTERNAL_ERROR
#endif
    },
    /* 20. include psk key mode ext in outers as well as both inner and outer */
    { encoded_inner_pre, sizeof(encoded_inner_pre),
      borked_outer12, sizeof(borked_outer12),
      encoded_inner_post, sizeof(encoded_inner_post),
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /* 21. too many outers */
    { NULL, 0,
      too_many_outers, sizeof(too_many_outers),
      NULL, 0,
      0, /* expected result */
      SSL_R_BAD_EXTENSION},
    /*
     * 22. no supported_versions hence TLSv1.2, with server set to
     * allow max tlsv1.3
     */
    { NULL, 0,
      no_supported_exts, sizeof(no_supported_exts),
      NULL, 0,
      0, /* expected result */
      SSL_R_UNSUPPORTED_PROTOCOL},
    /*
     * 23. no supported_versions hence TLSv1.2, with server set to
     * allow max tlsv1.2
     */
    { NULL, 0,
      no_supported_exts, sizeof(no_supported_exts),
      NULL, 0,
      0, /* expected result */
      SSL_R_NO_PROTOCOLS_AVAILABLE},
    /*
     * 24. no supported_versions hence TLSv1.2, with server set to
     * allow min tlsv1.2
     */
    { NULL, 0,
      no_supported_exts, sizeof(no_supported_exts),
      NULL, 0,
      0, /* expected result */
      SSL_R_UNSUPPORTED_PROTOCOL},
    /* 25. smuggled TLSv1.2 CH */
    { NULL, 0,
      tlsv12_inner, sizeof(tlsv12_inner),
      NULL, 0,
      0, /* expected result */
      SSL_R_UNSUPPORTED_PROTOCOL},

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

#define OSSL_ECH_BORK_NONE 0
#define OSSL_ECH_BORK_FLIP 1
#define OSSL_ECH_BORK_HRR (1 << 1)
#define OSSL_ECH_BORK_SHORT_HRR_CONFIRM (1 << 2)
#define OSSL_ECH_BORK_LONG_HRR_CONFIRM (1 << 3)
#define OSSL_ECH_BORK_GREASE (1 << 4)
#define OSSL_ECH_BORK_REPLACE (1 << 5)

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
     shortech, sizeof(shortech), 0, SSL_R_LENGTH_MISMATCH},
    /* 7. too-long HRR.exts ECH confirmation value */
    {OSSL_ECH_BORK_HRR | OSSL_ECH_BORK_REPLACE,
     longech, sizeof(longech), 0, SSL_R_BAD_EXTENSION},

};

/*
 * Test vectors for badly encoded ECH extension values for
 * the outer ClientHelllo. We grab the outbound ClientHello
 * and overwrite these values in the appropriate place. That
 * will always break the TLS connection, even with a correct
 * encoding, as we're breaking the transcript, but we expect
 * decoding to catch these and to get 'bad extension' errors
 * in most cases.
 *
 * Note that the code for these tests could be more terse as
 * declaring a separate buffer for each bad value is quite
 * repetitive, but doing it this way is more readable and more
 * easily varied/extended.
 */

/* an entire correctly encoded ECH (len = 190) */
static unsigned char entire_encoded_ech[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00, /* outer ECH */
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c, /* config id */
    0x00, 0x20, /* encap len then encap val */
    0x59, 0x87, 0xbe, 0x13, 0xd0, 0xf1, 0x0e, 0x23,
    0xcb, 0x28, 0x26, 0xc2, 0x88, 0xd0, 0x8f, 0xac,
    0x04, 0x99, 0x54, 0x30, 0xa2, 0x0f, 0xfe, 0x53,
    0xf5, 0xa5, 0x92, 0x01, 0xb1, 0x56, 0xd2, 0x3f,
    0x00, 0x90, /* payload len then payload */
    0x9e, 0xe6, 0xed, 0x1d, 0xe2, 0xef, 0x30, 0xb0,
    0x91, 0x00, 0xdc, 0x90, 0x21, 0x9e, 0x5e, 0x6f,
    0xcb, 0xb9, 0xb3, 0x05, 0xdd, 0xac, 0x97, 0x71,
    0xf0, 0x2d, 0x48, 0xf7, 0x01, 0xf4, 0x68, 0x0c,
    0xb4, 0xbe, 0x78, 0x3c, 0xa3, 0xcb, 0x6a, 0x16,
    0x7a, 0xfc, 0x33, 0xcd, 0x12, 0xf3, 0x00, 0x2f,
    0x3e, 0xaa, 0xef, 0x7c, 0x26, 0xd3, 0x6f, 0x46,
    0x8e, 0xb8, 0x54, 0x4c, 0x6a, 0xc3, 0x85, 0x92,
    0x44, 0xc1, 0xe2, 0x03, 0xfe, 0xfc, 0xca, 0xff,
    0x3b, 0x03, 0x9a, 0xf0, 0xd8, 0xe7, 0x2d, 0xb0,
    0xe3, 0x64, 0x9f, 0xb9, 0x78, 0xd3, 0xca, 0x4c,
    0xa2, 0xdd, 0x1f, 0x68, 0x9a, 0x9b, 0xcc, 0xb9,
    0x79, 0x59, 0xb4, 0xac, 0x4e, 0x7d, 0xce, 0xa3,
    0xc7, 0x23, 0xe6, 0x1c, 0xcd, 0x8d, 0xaa, 0xaa,
    0xdb, 0x21, 0xa1, 0xec, 0xb8, 0xbe, 0x53, 0x60,
    0x4f, 0xf4, 0x0b, 0xef, 0xad, 0x1d, 0x45, 0x62,
    0x65, 0x88, 0xfe, 0x15, 0x47, 0x25, 0x61, 0xa5,
    0x65, 0x7a, 0x17, 0xaa, 0x08, 0x3f, 0xe8, 0xf2
};

/* overall length too much */
static unsigned char too_long_ech[] = {
    0xfe, 0x0d, 0xFF, 0xba, /* ext type & length */
};

/* overall length too short */
static unsigned char too_short_ech[] = {
    0xfe, 0x0d, 0x00, 0x00, /* ext type & length */
};

/* no inner/outer value */
static unsigned char no_innerouter_ech[] = {
    0xfe, 0x0d, 0x00, 0x00, /* ext type & length */
    0x00,
};

/* ECH inner/outer bad value */
static unsigned char bad_innerouter_ech[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0xFF,
};

/* too short to get to KDF */
static unsigned char too_short_kdf[] = {
    0xfe, 0x0d, 0x00, 0x02, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
};

/* too short to get to AEAD */
static unsigned char too_short_aead[] = {
    0xfe, 0x0d, 0x00, 0x04, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
};

/* too short to get to config_id */
static unsigned char too_short_cid[] = {
    0xfe, 0x0d, 0x00, 0x05, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
};

/* zero length encap (only ok in HRR) */
static unsigned char zero_encap_len[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00, 0x00,
};

/* too short to get to encap_len  */
static unsigned char too_short_encap_len[] = {
    0xfe, 0x0d, 0x00, 0x07, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00
};

/* too long encap len */
static unsigned char too_long_encap_len[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0xFF, 0xFF,
};

/* bit long encap len (more than extension) */
static unsigned char bit_long_encap_len[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00, 0xFF,
};

/* too short to get to payload_len */
static unsigned char too_short_payload_len[] = {
    0xfe, 0x0d, 0x00, 0x29, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00, 0x20, /* encap len then encap val */
    0x59, 0x87, 0xbe, 0x13, 0xd0, 0xf1, 0x0e, 0x23,
    0xcb, 0x28, 0x26, 0xc2, 0x88, 0xd0, 0x8f, 0xac,
    0x04, 0x99, 0x54, 0x30, 0xa2, 0x0f, 0xfe, 0x53,
    0xf5, 0xa5, 0x92, 0x01, 0xb1, 0x56, 0xd2, 0x3f,
    0x00, 0x90, /* payload len then payload */
};

/* bit long payload_len */
static unsigned char bit_long_payload_len[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00, 0x20, /* encap len then encap val */
    0x59, 0x87, 0xbe, 0x13, 0xd0, 0xf1, 0x0e, 0x23,
    0xcb, 0x28, 0x26, 0xc2, 0x88, 0xd0, 0x8f, 0xac,
    0x04, 0x99, 0x54, 0x30, 0xa2, 0x0f, 0xfe, 0x53,
    0xf5, 0xa5, 0x92, 0x01, 0xb1, 0x56, 0xd2, 0x3f,
    0x00, 0xba, /* payload len then payload */
};

/* zero payload_len */
static unsigned char zero_payload_len[] = {
    0xfe, 0x0d, 0x00, 0xba, /* ext type & length */
    0x00,
    0x00, 0x01, 0x00, 0x01, /* cipher suite KDF, AEAD */
    0x7c,
    0x00, 0x20, /* encap len then encap val */
    0x59, 0x87, 0xbe, 0x13, 0xd0, 0xf1, 0x0e, 0x23,
    0xcb, 0x28, 0x26, 0xc2, 0x88, 0xd0, 0x8f, 0xac,
    0x04, 0x99, 0x54, 0x30, 0xa2, 0x0f, 0xfe, 0x53,
    0xf5, 0xa5, 0x92, 0x01, 0xb1, 0x56, 0xd2, 0x3f,
    0x00, 0x00, /* payload len then payload */
};

/*
 * Structrue for test vectors for ECH in the outer CH
 *  - value to use to overwrite encoded ECH
 *  - expected result (1 for good, 0 for bad)
 *  - expected error reason in the case of bad
 *
 * For each test, we replace the first |len| octets of the
 * ECH extension in the outer CH with the associated |val|.
 *
 * Note that the overall length of the outer CH needs to
 * be mainained as otherwise outer length fields that are not
 * re-computed will be wrong. (We include a test of that as
 * well.) A radical change in the content of encoded inner
 * values (e.g. eliminating compression entirely) could break
 * these tests, but minor changes should have no effect due to
 * padding. (Such a radical change showing up as a fail of
 * these tests is arguably a good outcome.)
 */
typedef struct {
    const unsigned char *val;
    size_t len;
    int rv_expected; /* expected result */
    int err_expected; /* expected error */
} TEST_ECHOUTER;

static TEST_ECHOUTER test_echs[] = {
    /* 1. basic case - copy to show test code works with no change */
    { NULL, 0, 1, SSL_ERROR_NONE},

    /* 2. good encoding/length but breaks TLS session integrity */
    { entire_encoded_ech, sizeof(entire_encoded_ech),
      0, /* expected result */
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC},
    /* 3. ECH length too long */
    { too_long_ech, sizeof(too_long_ech),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 4. ECH length too short */
    { too_short_ech, sizeof(too_short_ech),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 5. no inner/outer value */
    { no_innerouter_ech, sizeof(no_innerouter_ech),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 6. inner/outer bad value */
    { bad_innerouter_ech, sizeof(bad_innerouter_ech),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 7. too_short_kdf value */
    { too_short_kdf, sizeof(too_short_kdf),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 8. too_short_aead value */
    { too_short_aead, sizeof(too_short_aead),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 9. too_short_cid value */
    { too_short_cid, sizeof(too_short_cid),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 10. zero_encap_len value */
    { zero_encap_len, sizeof(zero_encap_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 11. too_short_encap_len value */
    { too_short_encap_len, sizeof(too_short_encap_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 12. too_long_encap_len value */
    { too_long_encap_len, sizeof(too_long_encap_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 13. bit_long_encap_len value */
    { bit_long_encap_len, sizeof(bit_long_encap_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 14.  too_short_payload_len value */
    { too_short_payload_len, sizeof(too_short_payload_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 15. bit_long_payload_len value */
    { bit_long_payload_len, sizeof(bit_long_payload_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
    /* 16. zero_payload_len value */
    { zero_payload_len, sizeof(zero_payload_len),
      0, /* expected result */ SSL_R_BAD_EXTENSION},
};

/*
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * sh is the SH buffer
 * sh_len is the length of the SH
 * exts points to offset of extensions
 * echoffset points to offset of ECH
 * echtype points to the ext type of the ECH
 * for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
static int ech_get_sh_offsets(const unsigned char *sh,
                              size_t sh_len, size_t *exts,
                              size_t *echoffset, uint16_t *echtype)
{
    unsigned int elen = 0, etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *shstart = NULL, *estart = NULL;
    PACKET pkt;
    size_t extlens = 0;
    int done = 0;
#ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
    size_t sessid_offset = 0;
    size_t sessid_len = 0;
#endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL)
        return 0;
    *exts = *echoffset = *echtype = 0;
    if (!PACKET_buf_init(&pkt, sh, sh_len))
        return 0;
    shstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION)
        return 1;
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_offset = PACKET_data(&pkt) - shstart) == 0
#endif
        || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_len = (size_t)pi_tmp) == 0
#endif
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
        || (*exts = PACKET_data(&pkt) - shstart) == 0
        || !PACKET_get_net_2(&pkt, &pi_tmp)) /* len(extensions) */
        return 0;
    extlens = (size_t)pi_tmp;
    if (extlens == 0) /* not an error, in theory */
        return 1;
    estart = PACKET_data(&pkt);
    while (PACKET_remaining(&pkt) > 0
           && (size_t)(PACKET_data(&pkt) - estart) < extlens
           && done < 1) {
        if (!PACKET_get_net_2(&pkt, &etype)
            || !PACKET_get_net_2(&pkt, &elen))
            return 0;
        if (etype == TLSEXT_TYPE_ech) {
            if (elen == 0)
                return 0;
            *echoffset = PACKET_data(&pkt) - shstart - 4;
            *echtype = etype;
#ifdef OSSL_ECH_SUPERVERBOSE
            echlen = elen + 4; /* type and length included */
#endif
            done++;
        }
        if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
            return 0;
    }
#ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ossl_ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ossl_ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
                  sessid_len);
    ossl_ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ossl_ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, echlen);
#endif
    return 1;
}

/* Do a HPKE seal of a padded encoded inner */
static int seal_encoded_inner(char **out, int *outlen,
                              unsigned char *ei, size_t eilen,
                              const char *ch, int chlen,
                              size_t echoffset, size_t echlen)
{
    int res = 0;
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
    *outlen = (int)choutlen;
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
    TEST_ECHOUTER *to = NULL;
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
    if (testcase == TESTCASE_ECH && msglen > 10 && msg[0] == SSL3_RT_HANDSHAKE
        && msg[5] == SSL3_MT_CLIENT_HELLO)
        is_ch = 1;

    if (testcase == TESTCASE_CH && is_ch == 1) {
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
        if (!TEST_true(ossl_ech_helper_get_ch_offsets((const unsigned char *)msg
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

    if (testcase == TESTCASE_ECH && is_ch == 1) {
        if (testiter >= (int)OSSL_NELEM(test_echs))
            return 0;
        to = &test_echs[testiter];
        if (!TEST_true(ossl_ech_helper_get_ch_offsets((const unsigned char *)msg
                                                      + SSL3_RT_HEADER_LENGTH
                                                      + SSL3_HM_HEADER_LENGTH,
                                                      msglen
                                                      - SSL3_RT_HEADER_LENGTH
                                                      - SSL3_HM_HEADER_LENGTH,
                                                      &sessid, &exts, &extlens,
                                                      &echoffset, &echtype, &echlen,
                                                      &snioffset, &snilen, &inner)))
            return 0;
        /* if it doesn't have an ECH just copy the entire input to output */
        if (echoffset == 0) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            *msgoutlen = msglen;
            return 1;
        }
        /* check for editing errors, the +4 is for ext type + len */
        if (to->len > (echlen + 4)) {
            TEST_info("manual sizing error");
            return 0;
        }
        if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
            return 0;
        *msgoutlen = msglen;
        /*
         * overwrite (some of) the outer ECH, in contrast to
         * the above case, here we're overwriting the ECH
         * ext type and length as well, the +9 is for record
         * layer framing as before
         */
        if (to->val != NULL) /* keep fuzz checker happy */
            memcpy(*msgout + echoffset + 9, to->val, to->len);
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
        if ((ts->borkage & OSSL_ECH_BORK_FLIP) != 0) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            if ((ts->borkage & OSSL_ECH_BORK_HRR) != 0) {
                rv = ech_get_sh_offsets((unsigned char *)msg + 9,
                                        msglen - 9,
                                        &exts, &echoffset,
                                        &echtype);
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
        if ((ts->borkage & OSSL_ECH_BORK_REPLACE) != 0 &&
            (ts->borkage & OSSL_ECH_BORK_HRR) != 0) {
            if (!TEST_ptr(*msgout = OPENSSL_memdup(msg, msglen)))
                return 0;
            rv = ech_get_sh_offsets((unsigned char *)msg + 9,
                                    msglen - 9,
                                    &exts, &echoffset, &echtype);
            if (!TEST_int_eq(rv, 1))
                return 0;
            if (echoffset > 0)
                memcpy(&((*msgout)[9 + echoffset]), ts->bork, ts->blen);
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

#define BIO_TYPE_CUSTOM_CORRUPT (0x80 | BIO_TYPE_FILTER)
#define BIO_TYPE_CUSTOM_SPLIT (0x81 | BIO_TYPE_FILTER)

static BIO_METHOD *method_tls_corrupt = NULL;

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

static int test_ch_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0, err = 0, connrv = 0, err_reason = 0;
    int exp_err = SSL_ERROR_NONE;
    TEST_ECHINNER *ti = NULL;
    const char *err_str = NULL;

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
    /* set server to be willing to only accept TLSv1.2 for test case 23 */
    if (testidx == 22
        && !TEST_true(SSL_CTX_set_max_proto_version(sctx, TLS1_2_VERSION)))
        goto end;
    /* set server to be willing to accept TLSv1.2 for test case 24 */
    if (testidx == 23
        && !TEST_true(SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION)))
        goto end;
    /* set client/server to be willing to accept TLSv1.2 for test case 25 */
    if (testidx == 24
        && !TEST_true(SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION))
        && !TEST_true(SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION)))
        goto end;
    if (!TEST_true(SSL_CTX_set1_echstore(sctx, es)))
        goto end;
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set1_ech_config_list(client, (unsigned char *)echconfig,
                                            echconfiglen)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (ti->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, ti->rv_expected))
        goto end;
    if (verbose) {
        err_str = ERR_reason_error_string(ti->err_expected);
        err_reason = ERR_GET_REASON(ti->err_expected);
        TEST_info("Expected error: %d/%s", err_reason, err_str);
    }
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            err_str = ERR_reason_error_string(err);
            if (verbose)
                TEST_info("Error reason: %d/%s", err_reason, err_str);
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
    const char *err_str = NULL;

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
    if (!TEST_true(SSL_CTX_set1_echstore(sctx, es)))
        goto end;
    if (!TEST_ptr(s_to_c_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
                                      s_to_c_fbio, NULL)))
        goto end;
    if ((ts->borkage & OSSL_ECH_BORK_GREASE) != 0) {
        if (!TEST_true(SSL_set_options(client, SSL_OP_ECH_GREASE)))
            goto end;
    } else {
        if (!TEST_true(SSL_set1_ech_config_list(client,
                                                (unsigned char *)echconfig,
                                                echconfiglen)))
            goto end;
    }
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
    if (connrv == 1 && (ts->borkage & OSSL_ECH_BORK_GREASE) != 0) {
        if (!TEST_true(SSL_ech_get1_retry_config(client, &retryconfig,
                                                 &retryconfiglen))
            || !TEST_ptr(retryconfig)
            || !TEST_int_ne((int)retryconfiglen, 0))
            goto end;
    }
    if (verbose) {
        err_str = ERR_reason_error_string(ts->err_expected);
        err_reason = ERR_GET_REASON(ts->err_expected);
        TEST_info("Expected error: %d/%s", err_reason, err_str);
    }
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            err_str = ERR_reason_error_string(err);
            if (verbose)
                TEST_info("Error reason: %d/%s", err_reason, err_str);
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

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static int test_ech_corrupt(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c_to_s_fbio;
    int testresult = 0, err = 0, connrv = 0, err_reason = 0;
    int exp_err = SSL_ERROR_NONE;
    TEST_ECHOUTER *to = NULL;
    const char *err_str = NULL;

    testcase = TESTCASE_ECH;
    testiter = testidx;
    to = &test_echs[testidx];
    if (verbose)
        TEST_info("Starting #%d", testidx + 1);
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    if (!TEST_true(SSL_CTX_set1_echstore(sctx, es)))
        goto end;
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_corrupt_filter())))
        goto end;
    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL,
                                      c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set1_ech_config_list(client, (unsigned char *)echconfig,
                                            echconfiglen)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(client, "foo.example.com")))
        goto end;
    exp_err = SSL_ERROR_SSL;
    if (to->err_expected == 0)
        exp_err = SSL_ERROR_NONE;
    connrv = create_ssl_connection(server, client, exp_err);
    if (!TEST_int_eq(connrv, to->rv_expected))
        goto end;
    if (verbose) {
        err_str = ERR_reason_error_string(to->err_expected);
        err_reason = ERR_GET_REASON(to->err_expected);
        TEST_info("Expected error: %d/%s", err_reason, err_str);
    }
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH corruption: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            err_str = ERR_reason_error_string(err);
            if (verbose)
                TEST_info("Error reason: %d/%s", err_reason, err_str);
        } while (err_reason != to->err_expected);
    }
    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

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

int setup_tests(void)
{
    OPTION_CHOICE o;
    BIO *in = NULL;

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

    /* make an OSSL_ECHSTORE for pem_kp1 */
    if ((in = BIO_new(BIO_s_mem())) == NULL
        || BIO_write(in, pem_kp1, (int)strlen(pem_kp1)) <= 0
        || !TEST_ptr(es = OSSL_ECHSTORE_new(libctx, propq))
        || !TEST_true(OSSL_ECHSTORE_read_pem(es, in, OSSL_ECH_FOR_RETRY)))
        goto err;
    BIO_free_all(in);
    in = NULL;
    hpke_infolen = bin_echconfiglen + 200;
    if (!TEST_ptr(hpke_info = OPENSSL_malloc(hpke_infolen)))
        goto err;
    /* +/- 2 is to drop the ECHConfigList length at the start */
    if (!TEST_true(ossl_ech_make_enc_info((unsigned char *)bin_echconfig + 2,
                                          bin_echconfiglen - 2,
                                          hpke_info, &hpke_infolen)))
        goto err;
    ADD_ALL_TESTS(test_ch_corrupt, OSSL_NELEM(test_inners));
    ADD_ALL_TESTS(test_sh_corrupt, OSSL_NELEM(test_shs));
    ADD_ALL_TESTS(test_ech_corrupt, OSSL_NELEM(test_echs));
    return 1;
err:
    BIO_free_all(in);
    return 0;
}

void cleanup_tests(void)
{
    bio_f_tls_corrupt_filter_free();
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(hpke_info);
    OSSL_ECHSTORE_free(es);
}
