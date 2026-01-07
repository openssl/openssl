/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "../testutil.h"
#include "output.h"
#include "tu_local.h"

#if defined __has_include
/* Any compiler you're going to run valgrind on has this */
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define OPENSSL_VALGRIND_H_INCLUDED
#endif
#endif /* defined(__has_include) */

/*
 * At some point we should consider looking at this function with a view to
 * moving most/all of this into onfree handlers in OSSL_LIB_CTX.
 */

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    int setup_res;
    int gi_ret;

    gi_ret = global_init();

    test_open_streams();

    if (!gi_ret) {
        test_printf_stderr("Global init failed - aborting\n");
        return ret;
    }

    if (!setup_test_framework(argc, argv))
        goto end;

    if ((setup_res = setup_tests()) > 0) {
        ret = run_tests(argv[0]);
        cleanup_tests();
        opt_check_usage();
    } else if (setup_res == 0) {
        opt_help(test_get_options());
    }
end:
    ret = pulldown_test_framework(ret);
    test_close_streams();
#if defined(OPENSSL_VALGRIND_H_INCLUDED) && defined(RUNNING_ON_VALGRIND)
    /*
     * Somewhat paradoxically, we do *NOT* want to clean up normally
     * when running tests using valgrind in order to test the suppression
     * file which we will ship with the distribution.
     *
     * If for any reason you actually wish to run the test under valgrind
     * but still call cleanup, just run it without OSSL_USE_VALGRIND set.
     */
    if (RUNNING_ON_VALGRIND && getenv(OSSL_USE_VALGRIND) != NULL)
        return ret;
#endif /* defined(OPENSSL_VALGRIND_H_INCLUDED) && defined(RUNNING_ON_VALGRIND) */

    OPENSSL_cleanup();
    return ret;
}
