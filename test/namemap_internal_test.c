/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/namemap.h"
#include "testutil.h"

#define NAME1 "name1"
#define NAME2 "name2"
#define ALIAS1 "alias1"
#define ALIAS1_UC "ALIAS1"

static int test_namemap(OSSL_NAMEMAP *nm)
{
    int num1 = ossl_namemap_add(nm, 0, NAME1);
    int num2 = ossl_namemap_add(nm, 0, NAME2);
    int num3 = ossl_namemap_add(nm, num1, ALIAS1);
    int num4 = ossl_namemap_add(nm, 0, ALIAS1_UC);
    int check1 = ossl_namemap_name2num(nm, NAME1);
    int check2 = ossl_namemap_name2num(nm, NAME2);
    int check3 = ossl_namemap_name2num(nm, ALIAS1);
    int check4 = ossl_namemap_name2num(nm, ALIAS1_UC);
    int false1 = ossl_namemap_name2num(nm, "foo");

    return TEST_int_ne(num1, 0)
        && TEST_int_ne(num2, 0)
        && TEST_int_eq(num1, num3)
        && TEST_int_eq(num3, num4)
        && TEST_int_eq(num1, check1)
        && TEST_int_eq(num2, check2)
        && TEST_int_eq(num3, check3)
        && TEST_int_eq(num4, check4)
        && TEST_int_eq(false1, 0);
}

static int test_namemap_independent(void)
{
    OSSL_NAMEMAP *nm = ossl_namemap_new();
    int ok = nm != NULL && test_namemap(nm);

    ossl_namemap_free(nm);
    return ok;
}

static int test_namemap_stored(void)
{
    OSSL_NAMEMAP *nm = ossl_namemap_stored(NULL);

    return nm != NULL
        && test_namemap(nm);
}

/*
 * Test that EVP_get_digestbyname() will use the namemap when it can't find
 * entries in the legacy method database.
 */
static int test_digestbyname(void)
{
    int id;
    OSSL_NAMEMAP *nm = ossl_namemap_stored(NULL);
    const EVP_MD *sha256, *foo;

    id = ossl_namemap_add(nm, 0, "SHA256");
    if (!TEST_int_ne(id, 0))
        return 0;
    if (!TEST_int_eq(ossl_namemap_add(nm, id, "foo"), id))
        return 0;

    sha256 = EVP_get_digestbyname("SHA256");
    if (!TEST_ptr(sha256))
        return 0;
    foo = EVP_get_digestbyname("foo");
    if (!TEST_ptr_eq(sha256, foo))
        return 0;

    return 1;
}

/*
 * Test that EVP_get_cipherbyname() will use the namemap when it can't find
 * entries in the legacy method database.
 */
static int test_cipherbyname(void)
{
    int id;
    OSSL_NAMEMAP *nm = ossl_namemap_stored(NULL);
    const EVP_CIPHER *aes128, *bar;

    id = ossl_namemap_add(nm, 0, "AES-128-CBC");
    if (!TEST_int_ne(id, 0))
        return 0;
    if (!TEST_int_eq(ossl_namemap_add(nm, id, "bar"), id))
        return 0;

    aes128 = EVP_get_cipherbyname("AES-128-CBC");
    if (!TEST_ptr(aes128))
        return 0;
    bar = EVP_get_cipherbyname("bar");
    if (!TEST_ptr_eq(aes128, bar))
        return 0;

    return 1;
}


int setup_tests(void)
{
    ADD_TEST(test_namemap_independent);
    ADD_TEST(test_namemap_stored);
    ADD_TEST(test_digestbyname);
    ADD_TEST(test_cipherbyname);
    return 1;
}
