/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "output.h"
#include "tu_local.h"

#include <string.h>
#include "../../e_os.h"

/* The size of memory buffers to display on failure */
#define MEM_BUFFER_SIZE     (33)

/*
 * A common routine to output test failure messages.  Generally this should not
 * be called directly, rather it should be called by the following functions.
 *
 * |desc| is a printf formatted description with arguments |args| that is
 * supplied by the user and |desc| can be NULL.  |type| is the data type
 * that was tested (int, char, ptr, ...).  |fmt| is a system provided
 * printf format with following arguments that spell out the failure
 * details i.e. the actual values compared and the operator used.
 *
 * The typical use for this is from an utility test function:
 *
 * int test6(const char *file, int line, int n) {
 *     if (n != 6) {
 *         test_fail_message(1, file, line, "int", "value %d is not %d", n, 6);
 *         return 0;
 *     }
 *     return 1;
 * }
 *
 * calling test6(3, "oops") will return 0 and produce out along the lines of:
 *      FAIL oops: (int) value 3 is not 6\n
 *
 * It general, test_fail_message should not be called directly.
 */
static void test_fail_message(const char *prefix, const char *file, int line,
                              const char *type, const char *fmt, ...)
            PRINTF_FORMAT(5, 6);

static void test_fail_message_va(const char *prefix, const char *file, int line,
                                 const char *type, const char *fmt, va_list ap)
{
    test_printf_stderr("%*s# %s: ", subtest_level(), "",
                       prefix != NULL ? prefix : "ERROR");
    if (type)
        test_printf_stderr("(%s)", type);
    if (fmt != NULL) {
        test_vprintf_stderr(fmt, ap);
    }
    if (file != NULL) {
        test_printf_stderr(" @ %s:%d", file, line);
    }
    test_printf_stderr("\n");
    test_flush_stderr();
}

static void test_fail_message(const char *prefix, const char *file, int line,
                              const char *type, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    test_fail_message_va(prefix, file, line, type, fmt, ap);
    va_end(ap);
}

void test_info_c90(const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va("INFO", NULL, -1, NULL, desc, ap);
    va_end(ap);
}

void test_info(const char *file, int line, const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va("INFO", file, line, NULL, desc, ap);
    va_end(ap);
}

void test_error_c90(const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message(NULL, NULL, -1, NULL, desc, ap);
    va_end(ap);
}

void test_error(const char *file, int line, const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va(NULL, file, line, NULL, desc, ap);
    va_end(ap);
}

void test_openssl_errors(void)
{
    ERR_print_errors_cb(openssl_error_cb, NULL);
}

/*
 * Define some comparisons between pairs of various types.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 *
 * In each case the functions produced are:
 *  int test_name_eq(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ne(const type t1, const type t2, const char *desc, ...);
 *  int test_name_lt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_le(const type t1, const type t2, const char *desc, ...);
 *  int test_name_gt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ge(const type t1, const type t2, const char *desc, ...);
 *
 * The t1 and t2 arguments are to be compared for equality, inequality,
 * less than, less than or equal to, greater than and greater than or
 * equal to respectively.  If the specified condition holds, the functions
 * return 1.  If the condition does not hold, the functions print a diagnostic
 * message and return 0.
 *
 * The desc argument is a printf format string followed by its arguments and
 * this is included in the output if the condition being tested for is false.
 */
#define DEFINE_COMPARISON(type, name, opname, op, fmt)                  \
    int test_ ## name ## _ ## opname(const char *file, int line,        \
                                     const char *s1, const char *s2,    \
                                     const type t1, const type t2)      \
    {                                                                   \
        if (t1 op t2)                                                   \
            return 1;                                                   \
        test_fail_message(NULL, file, line, #type,                      \
                          "%s [" fmt "] " #op " %s [" fmt "]",          \
                          s1, t1, s2, t2);                              \
        return 0;                                                       \
    }

#define DEFINE_COMPARISONS(type, name, fmt)                             \
    DEFINE_COMPARISON(type, name, eq, ==, fmt)                          \
    DEFINE_COMPARISON(type, name, ne, !=, fmt)                          \
    DEFINE_COMPARISON(type, name, lt, <, fmt)                           \
    DEFINE_COMPARISON(type, name, le, <=, fmt)                          \
    DEFINE_COMPARISON(type, name, gt, >, fmt)                           \
    DEFINE_COMPARISON(type, name, ge, >=, fmt)

DEFINE_COMPARISONS(int, int, "%d")
DEFINE_COMPARISONS(unsigned int, uint, "%u")
DEFINE_COMPARISONS(char, char, "%c")
DEFINE_COMPARISONS(unsigned char, uchar, "%u")
DEFINE_COMPARISONS(long, long, "%ld")
DEFINE_COMPARISONS(unsigned long, ulong, "%lu")
DEFINE_COMPARISONS(size_t, size_t, "%zu")

DEFINE_COMPARISON(void *, ptr, eq, ==, "%p")
DEFINE_COMPARISON(void *, ptr, ne, !=, "%p")

int test_ptr_null(const char *file, int line, const char *s, const void *p)
{
    if (p == NULL)
        return 1;
    test_fail_message(NULL, file, line, "ptr", "%s [%p] == NULL", s, p);
    return 0;
}

int test_ptr(const char *file, int line, const char *s, const void *p)
{
    if (p != NULL)
        return 1;
    test_fail_message(NULL, file, line, "ptr", "%s [%p] != NULL", s, p);
    return 0;
}

int test_true(const char *file, int line, const char *s, int b)
{
    if (b)
        return 1;
    test_fail_message(NULL, file, line, "bool", "%s [false] == true", s);
    return 0;
}

int test_false(const char *file, int line, const char *s, int b)
{
    if (!b)
        return 1;
    test_fail_message(NULL, file, line, "bool", "%s [true] == false", s);
    return 0;
}

static const char *print_string_maybe_null(const char *s)
{
    return s == NULL ? "(NULL)" : s;
}

int test_str_eq(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if (s1 == NULL && s2 == NULL)
      return 1;
    if (s1 == NULL || s2 == NULL || strcmp(s1, s2) != 0) {
        test_fail_message(NULL, file, line, "string", "%s [%s] == %s [%s]",
                          st1, print_string_maybe_null(s1),
                          st2, print_string_maybe_null(s2));
        return 0;
    }
    return 1;
}

int test_str_ne(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (s1 == NULL || strcmp(s1, s2) == 0) {
        test_fail_message(NULL, file, line, "string", "%s [%s] != %s [%s]",
                          st1, print_string_maybe_null(s1),
                          st2, print_string_maybe_null(s2));
        return 0;
    }
    return 1;
}

int test_strn_eq(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, const char *s2, size_t len)
{
    int prec = (int)len;

    if (s1 == NULL && s2 == NULL)
      return 1;
    if (s1 == NULL || s2 == NULL || strncmp(s1, s2, len) != 0) {
        test_fail_message(NULL, file, line, "string", "%.s [%.*s] == %s [%.*s]",
                          st1, prec, print_string_maybe_null(s1),
                          st2, prec, print_string_maybe_null(s2));
        return 0;
    }
    return 1;
}

int test_strn_ne(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, const char *s2, size_t len)
{
    int prec = (int)len;

    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (s1 == NULL || strncmp(s1, s2, len) == 0) {
        test_fail_message(NULL, file, line, "string", "%s [%.*s] != %s [%.*s]",
                          st1, prec, print_string_maybe_null(s1),
                          st2, prec, print_string_maybe_null(s2));
        return 0;
    }
    return 1;
}

/*
 * We could use OPENSSL_buf2hexstr() to do this but trying to allocate memory
 * in a failure state isn't generally a great idea and if it fails, we want a
 * fall back position using caller supplied buffers.
 *
 * If the return value is different from the buffer supplied, it needs to be
 * freed by the caller.
 */
static char *print_mem_maybe_null(const void *s, size_t n,
                                  char outbuf[MEM_BUFFER_SIZE])
{
    size_t i;
    const unsigned char *p = (const unsigned char *)s;
    char *out = outbuf;
    int pad = 2 * n >= MEM_BUFFER_SIZE;

    if (s == NULL)
        return strcpy(outbuf, "(NULL)");
    if (pad) {
        if ((out = OPENSSL_malloc(2 * n + 1)) == NULL) {
            out = outbuf;
            n = (MEM_BUFFER_SIZE - 4) / 2;
        } else {
            pad = 0;
        }
    }

    for (i = 0; i < 2 * n; ) {
        const unsigned char c = *p++;
        out[i++] = "0123456789abcdef"[c >> 4];
        out[i++] = "0123456789abcdef"[c & 15];
    }
    if (pad) {
        out[i++] = '.';
        out[i++] = '.';
        out[i++] = '.';
    }
    out[i] = '\0';

    return out;
}

int test_mem_eq(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    char b1[MEM_BUFFER_SIZE], b2[MEM_BUFFER_SIZE];

    if (s1 == NULL && s2 == NULL)
        return 1;
    if (n1 != n2 || s1 == NULL || s2 == NULL || memcmp(s1, s2, n1) != 0) {
        char *m1 = print_mem_maybe_null(s1, n1, b1);
        char *m2 = print_mem_maybe_null(s2, n2, b2);

        test_fail_message(NULL, file, line, "memory",
                          "%s %s [%zu] == %s %s [%zu]",
                          st1, m1, n1, st2, m2, n2);
        if (m1 != b1)
            OPENSSL_free(m1);
        if (m2 != b2)
            OPENSSL_free(m2);
        return 0;
    }
    return 1;
}

int test_mem_ne(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    char b1[MEM_BUFFER_SIZE], b2[MEM_BUFFER_SIZE];

    if ((s1 == NULL) ^ (s2 == NULL))
        return 1;
    if (n1 != n2)
        return 1;
    if (s1 == NULL || memcmp(s1, s2, n1) == 0) {
        char *m1 = print_mem_maybe_null(s1, n1, b1);
        char *m2 = print_mem_maybe_null(s2, n2, b2);

        test_fail_message(NULL, file, line, "memory",
                          "%s %s [%zu] != %s %s [%zu]",
                          st1, m1, n1, st2, m2, n2);
        if (m1 != b1)
            OPENSSL_free(m1);
        if (m2 != b2)
            OPENSSL_free(m2);
        return 0;
    }
    return 1;
}
