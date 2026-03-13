/*
 * Copyright 2012-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <string.h>

#include "internal/deprecated.h"

#include <openssl/e_os2.h>
#include <openssl/macros.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/nelem.h"
#include "testutil.h"

struct set_name_fn {
    int (*fn)(X509 *, const char *);
    const char *name;
    int host;
    int email;
};

static struct gennamedata {
    const unsigned char der[22];
    size_t derlen;
} gennames[] = {
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     SEQUENCE {}
       *   }
       * }
       */
        {
            0xa0, 0x13, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x02, 0x30, 0x00 },
        21 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     [APPLICATION 0] {}
       *   }
       * }
       */
        {
            0xa0, 0x13, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x02, 0x60, 0x00 },
        21 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x0c, 0x01, 0x61 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.2 }
       *   [0] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x02, 0xa0, 0x03, 0x0c, 0x01, 0x61 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     UTF8String { "b" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x0c, 0x01, 0x62 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     BOOLEAN { TRUE }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x01, 0x01, 0xff },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     BOOLEAN { FALSE }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x01, 0x01, 0x00 },
        22 },
    { /* [1 PRIMITIVE] { "a" } */
        {
            0x81, 0x01, 0x61 },
        3 },
    { /* [1 PRIMITIVE] { "b" } */
        {
            0x81, 0x01, 0x62 },
        3 },
    { /* [2 PRIMITIVE] { "a" } */
        {
            0x82, 0x01, 0x61 },
        3 },
    { /* [2 PRIMITIVE] { "b" } */
        {
            0x82, 0x01, 0x62 },
        3 },
    { /*
       * [4] {
       *   SEQUENCE {
       *     SET {
       *       SEQUENCE {
       *         # commonName
       *         OBJECT_IDENTIFIER { 2.5.4.3 }
       *         UTF8String { "a" }
       *       }
       *     }
       *   }
       * }
       */
        {
            0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55,
            0x04, 0x03, 0x0c, 0x01, 0x61 },
        16 },
    { /*
       * [4] {
       *   SEQUENCE {
       *     SET {
       *       SEQUENCE {
       *         # commonName
       *         OBJECT_IDENTIFIER { 2.5.4.3 }
       *         UTF8String { "b" }
       *       }
       *     }
       *   }
       * }
       */
        {
            0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55,
            0x04, 0x03, 0x0c, 0x01, 0x62 },
        16 },
    { /*
       * [5] {
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x61 },
        7 },
    { /*
       * [5] {
       *   [1] {
       *     UTF8String { "b" }
       *   }
       * }
       */
        {
            0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x62 },
        7 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String {}
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x09, 0xa0, 0x02, 0x0c, 0x00, 0xa1, 0x03, 0x0c, 0x01, 0x61 },
        11 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String { "a" }
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x0a, 0xa0, 0x03, 0x0c, 0x01, 0x61, 0xa1, 0x03, 0x0c, 0x01,
            0x61 },
        12 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String { "b" }
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x0a, 0xa0, 0x03, 0x0c, 0x01, 0x62, 0xa1, 0x03, 0x0c, 0x01,
            0x61 },
        12 },
    { /* [6 PRIMITIVE] { "a" } */
        {
            0x86, 0x01, 0x61 },
        3 },
    { /* [6 PRIMITIVE] { "b" } */
        {
            0x86, 0x01, 0x62 },
        3 },
    { /* [7 PRIMITIVE] { `11111111` } */
        {
            0x87, 0x04, 0x11, 0x11, 0x11, 0x11 },
        6 },
    { /* [7 PRIMITIVE] { `22222222`} */
        {
            0x87, 0x04, 0x22, 0x22, 0x22, 0x22 },
        6 },
    { /* [7 PRIMITIVE] { `11111111111111111111111111111111` } */
        {
            0x87, 0x10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
        18 },
    { /* [7 PRIMITIVE] { `22222222222222222222222222222222` } */
        {
            0x87, 0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 },
        18 },
    { /* [8 PRIMITIVE] { 1.2.840.113554.4.1.72585.2.1 } */
        {
            0x88, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04, 0x01, 0x84,
            0xb7, 0x09, 0x02, 0x01 },
        15 },
    { /* [8 PRIMITIVE] { 1.2.840.113554.4.1.72585.2.2 } */
        {
            0x88, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04, 0x01, 0x84,
            0xb7, 0x09, 0x02, 0x02 },
        15 },
    { /*
       * Regression test for CVE-2023-0286.
       */
        {
            0xa3, 0x00 },
        2 }
};

static int test_GENERAL_NAME_cmp(void)
{
    size_t i, j;
    GENERAL_NAME **namesa = OPENSSL_malloc(sizeof(*namesa)
        * OSSL_NELEM(gennames));
    GENERAL_NAME **namesb = OPENSSL_malloc(sizeof(*namesb)
        * OSSL_NELEM(gennames));
    int testresult = 0;

    if (!TEST_ptr(namesa) || !TEST_ptr(namesb))
        goto end;

    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        const unsigned char *derp = gennames[i].der;

        /*
         * We create two versions of each GENERAL_NAME so that we ensure when
         * we compare them they are always different pointers.
         */
        namesa[i] = d2i_GENERAL_NAME(NULL, &derp, (long)gennames[i].derlen);
        derp = gennames[i].der;
        namesb[i] = d2i_GENERAL_NAME(NULL, &derp, (long)gennames[i].derlen);
        if (!TEST_ptr(namesa[i]) || !TEST_ptr(namesb[i]))
            goto end;
    }

    /* Every name should be equal to itself and not equal to any others. */
    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        for (j = 0; j < OSSL_NELEM(gennames); j++) {
            if (i == j) {
                if (!TEST_int_eq(GENERAL_NAME_cmp(namesa[i], namesb[j]), 0))
                    goto end;
            } else {
                if (!TEST_int_ne(GENERAL_NAME_cmp(namesa[i], namesb[j]), 0))
                    goto end;
            }
        }
    }
    testresult = 1;

end:
    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        if (namesa != NULL)
            GENERAL_NAME_free(namesa[i]);
        if (namesb != NULL)
            GENERAL_NAME_free(namesb[i]);
    }
    OPENSSL_free(namesa);
    OPENSSL_free(namesb);

    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_GENERAL_NAME_cmp);
    return 1;
}
