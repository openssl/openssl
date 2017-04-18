/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"

#include <openssl/crypto.h>
#include <openssl/bio.h>

BIO *bio_out = NULL;
BIO *bio_err = NULL;

#ifdef OPENSSL_USE_APPLINK
/*
 * Using BIO_new_fd() obligates the use of applinks on platforms where it's
 * relevant.  Because it becomes a module of the libtestutil library and would
 * be disregarded if not actively referred to, we have this dummy that does
 * exactly this.  For any module that uses the rest of the routines here,
 * OPENSSL_Applink should tag along for sure.
 */
void Applink_dummy(void);
void Applink_dummy(void)
{
    OPENSSL_EXTERN void OPENSSL_Applink(void);

    OPENSSL_Applink();
}
/* Generate an error for anyone who tries to actually use this dummy */
# define Applink_dummy "DON'T USE THIS"
#endif

void test_open_streams(void)
{
    bio_out = BIO_new_fd(1, 0);
    bio_err = BIO_new_fd(2, 0);

    OPENSSL_assert(bio_out != NULL);
    OPENSSL_assert(bio_err != NULL);
}

void test_close_streams(void)
{
    BIO_free(bio_out);
    BIO_free(bio_err);
}

int test_puts_stdout(const char *str)
{
    return BIO_puts(bio_out, str);
}

int test_puts_stderr(const char *str)
{
    return BIO_puts(bio_err, str);
}

int test_vprintf_stdout(const char *fmt, va_list ap)
{
    return BIO_vprintf(bio_out, fmt, ap);
}

int test_vprintf_stderr(const char *fmt, va_list ap)
{
    return BIO_vprintf(bio_err, fmt, ap);
}

int test_flush_stdout(void)
{
    return BIO_flush(bio_out);
}

int test_flush_stderr(void)
{
    return BIO_flush(bio_err);
}
