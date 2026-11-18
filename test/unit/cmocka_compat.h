/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_UNIT_CMOCKA_COMPAT_H
#define OSSL_TEST_UNIT_CMOCKA_COMPAT_H

#include <cmocka.h>

/* cmocka 2.x ships the version macros in a separate header; 1.x has none */
#if defined(__has_include)
#if __has_include(<cmocka_version.h>)
#include <cmocka_version.h>
#endif
#endif

/*
 * cmocka 2.x deprecated expect_value() and check_expected() in favour of
 * explicitly signed or unsigned variants.  The unsigned variants keep
 * the old semantics exactly (the old macros cast to uintmax_t), so the
 * test sources use them; when building against cmocka 1.x, which lacks
 * them, map them back onto the old names.  This header is the single
 * revert point once cmocka 1.x no longer needs supporting.
 */
#if !defined(expect_uint_value)
#define expect_uint_value(function, parameter, value) \
    expect_value(function, parameter, value)
#define expect_int_value(function, parameter, value) \
    expect_value(function, parameter, value)
#endif
#if !defined(check_expected_uint)
#define check_expected_uint(parameter) check_expected(parameter)
#define check_expected_int(parameter) check_expected(parameter)
#endif

/* cmocka 2.x renamed this cast helper */
#if !defined(cast_ptr_to_uintmax_type)
#define cast_ptr_to_uintmax_type(value) \
    ((uintmax_t)(uintptr_t)(value))
#endif

/*
 * Checking a function pointer parameter: with cmocka 2.x,
 * check_expected_ptr() trips -pedantic (it stores into a void * field)
 * and the uint variants reject pointers, so neither accepts a function
 * pointer.  This checks by uintmax_t representation on both versions;
 * the parameter must appear bare, as its name is stringified for
 * cmocka's parameter lookup.
 */
#if defined(CMOCKA_VERSION_MAJOR) && CMOCKA_VERSION_MAJOR >= 2
#define check_expected_fnptr(parameter)                       \
    _check_expected(__func__, #parameter, __FILE__, __LINE__, \
        (CMockaValueData) { .uint_val = (uintmax_t)(parameter) })
#else
#define check_expected_fnptr(parameter)                       \
    _check_expected(__func__, #parameter, __FILE__, __LINE__, \
        (uintmax_t)(parameter))
#endif

#endif /* OSSL_TEST_UNIT_CMOCKA_COMPAT_H */
