/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Printing an ML-KEM private key must report failure when the public key
 * part cannot be written.  The key is printed once to a memory BIO to find
 * where "ek:" starts, then again to a BIO that accepts exactly that many
 * bytes and fails every later write.
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "testutil.h"

static long write_limit, written;

static int limited_write(BIO *b, const char *data, int len)
{
    if (written + len > write_limit)
        return -1;
    written += len;
    return len;
}

static int limited_puts(BIO *b, const char *s)
{
    return limited_write(b, s, (int)strlen(s));
}

static long limited_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    return cmd == BIO_CTRL_FLUSH;
}

static int limited_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static const char *key_types[] = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
};

static int test_print_public_part_fails(int idx)
{
    EVP_PKEY *pkey = NULL;
    BIO *mem = NULL, *limited = NULL;
    BIO_METHOD *meth = NULL;
    char *text;
    long text_len, i, ek = -1;
    int ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, key_types[idx]))
        || !TEST_ptr(mem = BIO_new(BIO_s_mem()))
        || !TEST_int_eq(EVP_PKEY_print_private(mem, pkey, 0, NULL), 1))
        goto end;
    text_len = BIO_get_mem_data(mem, &text);
    for (i = 0; ek < 0 && i + 3 <= text_len; i++)
        if (memcmp(text + i, "ek:", 3) == 0)
            ek = i;
    if (!TEST_long_gt(ek, 0))
        goto end;
    write_limit = ek;
    written = 0;

    if (!TEST_ptr(meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
                      "limited write"))
        || !TEST_true(BIO_meth_set_write(meth, limited_write))
        || !TEST_true(BIO_meth_set_puts(meth, limited_puts))
        || !TEST_true(BIO_meth_set_ctrl(meth, limited_ctrl))
        || !TEST_true(BIO_meth_set_create(meth, limited_create))
        || !TEST_ptr(limited = BIO_new(meth)))
        goto end;

    /* The private part fits, the public part does not */
    if (!TEST_int_eq(EVP_PKEY_print_private(limited, pkey, 0, NULL), 0))
        goto end;
    ret = 1;
end:
    BIO_free(limited);
    BIO_meth_free(meth);
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
#ifdef OPENSSL_NO_ML_KEM
    return TEST_skip("ML-KEM is disabled");
#else
    ADD_ALL_TESTS(test_print_public_part_fails, OSSL_NELEM(key_types));
    return 1;
#endif
}
