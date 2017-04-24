/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "testutil.h"

/* Use a buffer size which is not aligned to block size */
#define BUFFER_SIZE     (8 * 1024) - 13

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
#endif


#ifndef OPENSSL_NO_AFALGENG
# include <linux/version.h>
# define K_MAJ   4
# define K_MIN1  1
# define K_MIN2  0
# if LINUX_VERSION_CODE <= KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)
/*
 * If we get here then it looks like there is a mismatch between the linux
 * headers and the actual kernel version, so we have tried to compile with
 * afalg support, but then skipped it in e_afalg.c. As far as this test is
 * concerned we behave as if we had been configured without support
 */
#  define OPENSSL_NO_AFALGENG
# endif
#endif

#ifndef OPENSSL_NO_AFALGENG
static int test_afalg_aes_128_cbc(void)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    unsigned char key[] = "\x5F\x4D\xCC\x3B\x5A\xA7\x65\xD6\
                           \x1D\x83\x27\xDE\xB8\x82\xCF\x99";
    unsigned char iv[] = "\x2B\x95\x99\x0A\x91\x51\x37\x4A\
                          \xBD\x8F\xF8\xC5\xA7\xA0\xFE\x08";

    unsigned char in[BUFFER_SIZE];
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    int encl, encf, decl, decf;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
            return 0;
    RAND_bytes(in, BUFFER_SIZE);

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1))
            || !TEST_true(EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE))
            || !TEST_true(EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)))
        goto end;
    encl += encf;

    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
            || !TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0))
            || !TEST_true(EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl))
            || !TEST_true(EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)))
        goto end;
    decl += decf;

    if (!TEST_int_eq(decl, BUFFER_SIZE)
            || !TEST_mem_eq(dbuf, BUFFER_SIZE, in, BUFFER_SIZE))
        goto end;

    ret = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
#endif

int main(int argc, char **argv)
{
    int ret = 0;

#ifdef OPENSSL_NO_ENGINE
    setup_test();
    ret = run_tests(argv[0]);
#else
    ENGINE_load_builtin_engines();
# ifndef OPENSSL_NO_STATIC_ENGINE
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);
# endif

    setup_test();

    if ((e = ENGINE_by_id("afalg")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load AFALG engine");
    } else {
# ifndef OPENSSL_NO_AFALGENG
        ADD_TEST(test_afalg_aes_128_cbc);
# endif
    }
    ret = run_tests(argv[0]);
    ENGINE_free(e);
#endif

    return finish_test(ret);
}
