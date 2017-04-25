/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include "../e_os.h"
#include "testutil.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef CHARSET_EBCDIC
# include <openssl/ebcdic.h>
#endif

static char test[][80] = {
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
};

static char *ret[] = {
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
};

static char *bigret = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";

static char *pt(unsigned char *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&(buf[i * 2]), "%02x", md[i]);
    return buf;
}

static int test_sha1(int i)
{
    EVP_MD_CTX *c;
    unsigned char md[SHA_DIGEST_LENGTH];
    const size_t tlen = strlen(test[i]);
    int testresult = 0;

    c = EVP_MD_CTX_new();
    if (!TEST_ptr(c))
        goto end;

# ifdef CHARSET_EBCDIC
    ebcdic2ascii(test[i], test[i], tlen);
# endif
    if (!TEST_true(EVP_Digest(test[i], tlen, md, NULL, EVP_sha1(), NULL))
        || !TEST_str_eq(pt(md), ret[i]))
        goto end;

    testresult = 1;
 end:
    EVP_MD_CTX_free(c);
    return testresult;
}

static int test_sha1_big(void)
{
    static unsigned char buf[1000];
    EVP_MD_CTX *c;
    unsigned char md[SHA_DIGEST_LENGTH];
    int i, testresult = 0;

    c = EVP_MD_CTX_new();
    if (!TEST_ptr(c))
        goto end;

    memset(buf, 'a', 1000);
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, 1000);
#endif                         /* CHARSET_EBCDIC */
    if (!TEST_true(EVP_DigestInit_ex(c, EVP_sha1(), NULL)))
        goto end;
    for (i = 0; i < 1000; i++)
        if (!TEST_true(EVP_DigestUpdate(c, buf, 1000)))
            goto end;
    if (!TEST_true(EVP_DigestFinal_ex(c, md, NULL)))
        goto end;

    if (!TEST_str_eq(pt(md), bigret))
        goto end;

    testresult = 1;
 end:
    EVP_MD_CTX_free(c);
    return testresult;
}

void register_tests(void)
{
    ADD_ALL_TESTS(test_sha1, OSSL_NELEM(test));
    ADD_TEST(test_sha1_big);
}
