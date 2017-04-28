/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
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

    /* flags */
    int subtest:1;
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
                   int num, int subtest)
{
    assert(num_tests != OSSL_NELEM(all_tests));
    all_tests[num_tests].test_case_name = test_case_name;
    all_tests[num_tests].param_test_fn = test_fn;
    all_tests[num_tests].num = num;
    all_tests[num_tests].subtest = subtest;
    ++num_tests;
    num_test_cases += num;
}

static int level = 0;

int subtest_level(void)
{
    return level;
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
    char *TAP_levels = getenv("HARNESS_OSSL_LEVEL");

    test_open_streams();

    level = TAP_levels != NULL ? 4 * atoi(TAP_levels) : 0;

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
    if (should_report_leaks()
        && CRYPTO_mem_leaks_cb(openssl_error_cb, NULL) <= 0)
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
        ERR_print_errors_cb(openssl_error_cb, NULL);
}

int run_tests(const char *test_prog_name)
{
    int num_failed = 0;
    char *verdict = NULL;
    int i, j;

    if (num_tests < 1)
        test_printf_stdout("%*s1..0 # Skipped: %s\n", level, "",
                           test_prog_name);
    else if (level > 0)
        test_printf_stdout("%*s1..%d # Subtest: %s\n", level, "", num_tests,
                           test_prog_name);
    else
        test_printf_stdout("%*s1..%d\n", level, "", num_tests);
    test_flush_stdout();

    for (i = 0; i != num_tests; ++i) {
        if (all_tests[i].num == -1) {
            int ret = all_tests[i].test_fn();

            test_flush_stdout();
            test_flush_stderr();

            verdict = "ok";
            if (!ret) {
                verdict = "not ok";
                ++num_failed;
            }
            test_printf_stdout("%*s%s %d - %s\n", level, "", verdict, i + 1,
                               all_tests[i].test_case_name);
            test_flush_stdout();
            finalize(ret);
        } else {
            int num_failed_inner = 0;

            level += 4;
            if (all_tests[i].subtest) {
                test_printf_stdout("%*s# Subtest: %s\n", level, "",
                                   all_tests[i].test_case_name);
                test_printf_stdout("%*s%d..%d\n", level, "", 1,
                                   all_tests[i].num);
                test_flush_stdout();
            }

            for (j = 0; j < all_tests[i].num; j++) {
                int ret = all_tests[i].param_test_fn(j);

                test_flush_stdout();
                test_flush_stderr();

                if (!ret)
                    ++num_failed_inner;

                finalize(ret);

                if (all_tests[i].subtest) {
                    verdict = "ok";
                    if (!ret) {
                        verdict = "not ok";
                        ++num_failed_inner;
                    }
                    test_printf_stdout("%*s%s %d\n", level, "", verdict, j + 1);
                    test_flush_stdout();
                }
            }

            level -= 4;
            verdict = "ok";
            if (num_failed_inner) {
                verdict = "not ok";
                ++num_failed;
            }
            test_printf_stdout("%*s%s %d - %s\n", level, "", verdict, i + 1,
                               all_tests[i].test_case_name);
            test_flush_stdout();
        }
    }
    if (num_failed != 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

