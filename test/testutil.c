/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* The size of memory buffers to display on failure */
#define MEM_BUFFER_SIZE     (21)

/*
 * Declares the structures needed to register each test case function.
 */
typedef struct test_info {
    const char *test_case_name;
    int (*test_fn) ();
    int (*param_test_fn)(int idx);
    int num;
} TEST_INFO;

static TEST_INFO all_tests[1024];
static int num_tests = 0;
/*
 * A parameterised tests runs a loop of test cases.
 * |num_test_cases| counts the total number of test cases
 * across all tests.
 */
static int num_test_cases = 0;

void add_test(const char *test_case_name, int (*test_fn) ())
{
    assert(num_tests != OSSL_NELEM(all_tests));
    all_tests[num_tests].test_case_name = test_case_name;
    all_tests[num_tests].test_fn = test_fn;
    all_tests[num_tests].num = -1;
    ++num_test_cases;
    ++num_tests;
}

void add_all_tests(const char *test_case_name, int(*test_fn)(int idx),
                   int num)
{
    assert(num_tests != OSSL_NELEM(all_tests));
    all_tests[num_tests].test_case_name = test_case_name;
    all_tests[num_tests].param_test_fn = test_fn;
    all_tests[num_tests].num = num;
    ++num_tests;
    num_test_cases += num;
}

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static int should_report_leaks()
{
    /*
     * When compiled with enable-crypto-mdebug, OPENSSL_DEBUG_MEMORY=0
     * can be used to disable leak checking at runtime.
     * Note this only works when running the test binary manually;
     * the test harness always enables OPENSSL_DEBUG_MEMORY.
     */
    char *mem_debug_env = getenv("OPENSSL_DEBUG_MEMORY");

    return mem_debug_env == NULL
        || (strcmp(mem_debug_env, "0") && strcmp(mem_debug_env, ""));
}
#endif


void setup_test()
{
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (should_report_leaks()) {
        CRYPTO_set_mem_debug(1);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    }
#endif
}

int finish_test(int ret)
{
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (should_report_leaks() && CRYPTO_mem_leaks_fp(stderr) <= 0)
        return EXIT_FAILURE;
#endif
    return ret;
}

static void finalize(int success)
{
    if (success)
        ERR_clear_error();
    else
        ERR_print_errors_fp(stderr);
}

int run_tests(const char *test_prog_name)
{
    int num_failed = 0;

    int i, j;

    printf("%s: %d test case%s\n", test_prog_name, num_test_cases,
           num_test_cases == 1 ? "" : "s");

    for (i = 0; i != num_tests; ++i) {
        if (all_tests[i].num == -1) {
            int ret = all_tests[i].test_fn();

            if (!ret) {
                printf("** %s failed **\n--------\n",
                       all_tests[i].test_case_name);
                ++num_failed;
            }
            finalize(ret);
        } else {
            for (j = 0; j < all_tests[i].num; j++) {
                int ret = all_tests[i].param_test_fn(j);

                if (!ret) {
                    printf("** %s failed test %d\n--------\n",
                           all_tests[i].test_case_name, j);
                    ++num_failed;
                }
                finalize(ret);
            }
        }
    }

    if (num_failed != 0) {
        printf("%s: %d test%s failed (out of %d)\n", test_prog_name,
               num_failed, num_failed != 1 ? "s" : "", num_test_cases);
        return EXIT_FAILURE;
    }
    printf("  All tests passed.\n");
    return EXIT_SUCCESS;
}

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
    fputs(prefix != NULL ? prefix : "ERROR", stderr);
    fputs(":", stderr);
    if (type)
        fprintf(stderr, " (%s)", type);
    if (fmt != NULL) {
        fputc(' ', stderr);
        vfprintf(stderr, fmt, ap);
    }
    if (file != NULL) {
        fprintf(stderr, " @ %s:%d", file, line);
    }
    fputc('\n', stderr);
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
DEFINE_COMPARISONS(size_t, size_t, "%" OSSLzu)

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

/*
 * We could use OPENSSL_buf2hexstr() to do this but trying to allocate memory
 * in a failure state isn't generally a great idea.
 */
static const char *print_mem_maybe_null(const void *s, size_t n,
                                        char out[MEM_BUFFER_SIZE])
{
    size_t i;
    const unsigned char *p = (const unsigned char *)s;
    int pad = 2*n >= MEM_BUFFER_SIZE;

    if (s == NULL)
        return "(NULL)";
    if (pad)
        n = MEM_BUFFER_SIZE-4;
    
    for (i=0; i<2*n; i++) {
        unsigned char c = (i & 1) != 0 ? p[i / 2] & 15 : p[i / 2] >> 4;
        out[i] = "0123456789abcdef"[c];
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
    if (n1 != n2) {
        test_fail_message(NULL, file, line, "memory",
                          "size mismatch %s %s [%"OSSLzu"] != %s %s [%"OSSLzu"]",
                          st1, print_mem_maybe_null(s1, n1, b1), n1,
                          st2, print_mem_maybe_null(s2, n2, b2), n2);
        return 0;
    }
    if (s1 == NULL || s2 == NULL || memcmp(s1, s2, n1) != 0) {
        test_fail_message(NULL, file, line, "memory",
                          "%s %s [%"OSSLzu"] != %s %s [%"OSSLzu"]",
                          st1, print_mem_maybe_null(s1, n1, b1), n1,
                          st2, print_mem_maybe_null(s2, n2, b2), n2);
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
        test_fail_message(NULL, file, line, "memory",
                          "%s %s [%"OSSLzu"] != %s %s [%"OSSLzu"]",
                          st1, print_mem_maybe_null(s1, n1, b1), n1,
                          st2, print_mem_maybe_null(s2, n2, b2), n2);
        return 0;
    }
    return 1;
}
