/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslv.h>
#include "testutil.h"

static int test(const char *op, int major, int minor, int patch)
{
    char buf[1000];

    snprintf(buf, sizeof(buf), "%s%d.%d.%d", op, major, minor, patch);
    return version_match(buf);
}

static int test_basic_version(void)
{
    return TEST_true(test("=", OPENSSL_VERSION_MAJOR,
                          OPENSSL_VERSION_MINOR,
                          OPENSSL_VERSION_PATCH))
            && TEST_true(test(">=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("<=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))

            && TEST_false(test("!", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test(">", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("<", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))

            && TEST_true(test("<=", OPENSSL_VERSION_MAJOR + 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("<=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR + 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("<=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH + 1))

            && TEST_true(test("<", OPENSSL_VERSION_MAJOR + 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("<", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR + 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("<", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH + 1))

            && TEST_false(test(">=", OPENSSL_VERSION_MAJOR + 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test(">=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR + 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test(">=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH + 1))

            && TEST_false(test(">", OPENSSL_VERSION_MAJOR + 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test(">", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR + 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test(">", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH + 1))

            && TEST_false(test("=", OPENSSL_VERSION_MAJOR + 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR + 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH + 1))

            && TEST_true(test("!", OPENSSL_VERSION_MAJOR + 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("!", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR + 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("!", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH + 1))

            && TEST_false(test("<=", OPENSSL_VERSION_MAJOR - 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("<=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR - 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("<=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH - 1))

            && TEST_false(test("<", OPENSSL_VERSION_MAJOR - 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("<", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR - 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("<", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH - 1))

            && TEST_true(test(">=", OPENSSL_VERSION_MAJOR - 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test(">=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR - 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test(">=", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH - 1))

            && TEST_true(test(">", OPENSSL_VERSION_MAJOR - 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test(">", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR - 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test(">", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH - 1))

            && TEST_false(test("=", OPENSSL_VERSION_MAJOR - 1,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR - 1,
                               OPENSSL_VERSION_PATCH))
            && TEST_false(test("=", OPENSSL_VERSION_MAJOR,
                               OPENSSL_VERSION_MINOR,
                               OPENSSL_VERSION_PATCH - 1))

            && TEST_true(test("!", OPENSSL_VERSION_MAJOR - 1,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("!", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR - 1,
                              OPENSSL_VERSION_PATCH))
            && TEST_true(test("!", OPENSSL_VERSION_MAJOR,
                              OPENSSL_VERSION_MINOR,
                              OPENSSL_VERSION_PATCH - 1));
}

static int test_compound_version(void)
{
    return TEST_false(version_match("<3.0.0 >=3.0.0"))
            && TEST_true(version_match(">=3.0.0 <9999.1.1"));
}

int setup_tests(void)
{
    ADD_TEST(&test_basic_version);
    ADD_TEST(&test_compound_version);
    return 1;
}
