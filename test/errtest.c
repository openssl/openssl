/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/err.h>

#include "testutil.h"

#if defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>
#else
# include <errno.h>
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
    ERR_get_error_line_data(NULL, NULL, &data, NULL);
    return TEST_str_eq(data, "hello world");
}

/* Test that setting a platform error sets the right values. */
static int platform_error(void)
{
    const char *file, *f, *data;
    int line;
    int l;
    unsigned long e;

    file = __FILE__;
    line = __LINE__ + 1; /* The error is generated on the next line */
    ERR_raise_data(ERR_LIB_SYS, ERR_R_INTERNAL_ERROR,
                   "calling %s()", "exit");
    if (!TEST_ulong_ne(e = ERR_get_error_line_data(&f, &l, &data, NULL), 0)
            || !TEST_int_eq(ERR_GET_REASON(e), ERR_R_INTERNAL_ERROR)
            || !TEST_int_eq(l, line)
            || !TEST_str_eq(f, file)
            || !TEST_str_eq(data, "calling exit()"))
        return 0;
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(preserves_system_error);
    ADD_TEST(vdata_appends);
    ADD_TEST(platform_error);
    return 1;
}
