/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/macros.h>

#include "testutil.h"

#if defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>
#else
# include <errno.h>
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
# define IS_HEX(ch) ((ch >= '0' && ch <='9') || (ch >= 'A' && ch <='F'))

static int test_print_error_format(void)
{
    /* Variables used to construct an error line */
    const char *func = OPENSSL_FUNC;
# ifndef OPENSSL_NO_FILENAMES
    const char *file = OPENSSL_FILE;
    const int line = OPENSSL_LINE;
# else
    const char *file = "";
    const int line = 0;
# endif
    /* The format for OpenSSL error lines */
    const char *expected_format = ":error::system library:%s:%s:%s:%d";
    /*-
     *                                                    ^^ ^^ ^^ ^^
     * function name -------------------------------------++ || || ||
     * reason string (system error string) ------------------++ || ||
     * file name -----------------------------------------------++ ||
     * line number ------------------------------------------------++
     */
    char expected[512];

    char *out = NULL, *p = NULL;
    int ret = 0, len;
    BIO *bio = NULL;
    const int syserr = EPERM;
    int reasoncode;

    /*
     * We set a mark here so we can clear the system error that we generate
     * with ERR_PUT_error().  That is, after all, just a simulation to verify
     * ERR_print_errors() output, not a real error.
     */
    ERR_set_mark();

    ERR_PUT_error(ERR_LIB_SYS, 0, syserr, file, line);
    reasoncode = ERR_GET_REASON(ERR_peek_error());

    if (!TEST_int_eq(reasoncode, syserr)) {
        ERR_pop_to_mark();
        goto err;
    }

    BIO_snprintf(expected, sizeof(expected), expected_format,
                 func, strerror(syserr), file, line);

    if (!TEST_ptr(bio = BIO_new(BIO_s_mem())))
        goto err;

    ERR_print_errors(bio);

    if (!TEST_int_gt(len = BIO_get_mem_data(bio, &out), 0))
        goto err;
    /* Skip over the variable thread id at the start of the string */
    for (p = out; *p != ':' && *p != 0; ++p) {
        if (!TEST_true(IS_HEX(*p)))
            goto err;
    }
    if (!TEST_true(*p != 0)
        || !TEST_strn_eq(expected, p, strlen(expected)))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    return ret;
}
#endif

/* Test that querying the error queue preserves the OS error. */
static int preserves_system_error(void)
{
#if defined(OPENSSL_SYS_WINDOWS)
    SetLastError(ERROR_INVALID_FUNCTION);
    ERR_get_error();
    return TEST_int_eq(GetLastError(), ERROR_INVALID_FUNCTION);
#else
    errno = EINVAL;
    ERR_get_error();
    return TEST_int_eq(errno, EINVAL);
#endif
}

/* Test that calls to ERR_add_error_[v]data append */
static int vdata_appends(void)
{
    const char *data;

    CRYPTOerr(0, ERR_R_MALLOC_FAILURE);
    ERR_add_error_data(1, "hello ");
    ERR_add_error_data(1, "world");
    ERR_peek_error_data(&data, NULL);
    return TEST_str_eq(data, "hello world");
}

static int raised_error(void)
{
    const char *f, *data;
    int l;
    unsigned long e;

    /*
     * When OPENSSL_NO_ERR or OPENSSL_NO_FILENAMES, no file name or line
     * number is saved, so no point checking them.
     */
#if !defined(OPENSSL_NO_FILENAMES) && !defined(OPENSSL_NO_ERR)
    const char *file;
    int line;

    file = __FILE__;
    line = __LINE__ + 2; /* The error is generated on the ERR_raise_data line */
#endif
    ERR_raise_data(ERR_LIB_NONE, ERR_R_INTERNAL_ERROR,
                   "calling exit()");
    if (!TEST_ulong_ne(e = ERR_get_error_all(&f, &l, NULL, &data, NULL), 0)
            || !TEST_int_eq(ERR_GET_REASON(e), ERR_R_INTERNAL_ERROR)
#if !defined(OPENSSL_NO_FILENAMES) && !defined(OPENSSL_NO_ERR)
            || !TEST_int_eq(l, line)
            || !TEST_str_eq(f, file)
#endif
            || !TEST_str_eq(data, "calling exit()"))
        return 0;
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(preserves_system_error);
    ADD_TEST(vdata_appends);
    ADD_TEST(raised_error);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_print_error_format);
#endif
    return 1;
}
