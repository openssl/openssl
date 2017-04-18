/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"

#include <string.h>
#include <assert.h>

#include "../../e_os.h"
#include <openssl/bio.h>

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
    ++num_tests;
    ++num_test_cases;
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


static int err_cb(const char *str, size_t len, void *u)
{
    return test_puts_stderr(str);
}

void setup_test()
{
    test_open_streams();

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
    if (should_report_leaks() && CRYPTO_mem_leaks_cb(err_cb, NULL) <= 0)
        return EXIT_FAILURE;
#endif

    test_close_streams();

    return ret;
}

static void finalize(int success)
{
    if (success)
        ERR_clear_error();
    else
        ERR_print_errors_cb(err_cb, NULL);
}

static void helper_printf_stdout(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    test_vprintf_stdout(fmt, ap);
    va_end(ap);
}

int run_tests(const char *test_prog_name)
{
    int num_failed = 0;
    int i, j;

    helper_printf_stdout("%s: %d test case%s\n", test_prog_name, num_test_cases,
                         num_test_cases == 1 ? "" : "s");
    test_flush_stdout();

    for (i = 0; i != num_tests; ++i) {
        if (all_tests[i].num == -1) {
            int ret = all_tests[i].test_fn();

            if (!ret) {
                helper_printf_stdout("** %s failed **\n--------\n",
                                     all_tests[i].test_case_name);
                test_flush_stdout();
                ++num_failed;
            }
            finalize(ret);
        } else {
            for (j = 0; j < all_tests[i].num; j++) {
                int ret = all_tests[i].param_test_fn(j);

                if (!ret) {
                    helper_printf_stdout("** %s failed test %d\n--------\n",
                                         all_tests[i].test_case_name, j);
                    test_flush_stdout();
                    ++num_failed;
                }
                finalize(ret);
            }
        }
    }

    if (num_failed != 0) {
        helper_printf_stdout("%s: %d test%s failed (out of %d)\n",
                             test_prog_name, num_failed,
                             num_failed != 1 ? "s" : "", num_test_cases);
        test_flush_stdout();
        return EXIT_FAILURE;
    }
    helper_printf_stdout("  All tests passed.\n");
    test_flush_stdout();
    return EXIT_SUCCESS;
}

