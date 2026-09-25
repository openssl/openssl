/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
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
 * Watchdog: abort a test program that runs longer than a fixed time limit.
 * A hung test otherwise consumes the entire CI job budget (e.g. 6 hours); the
 * watchdog turns that into a prompt failure that names the test and, where the
 * environment enables core dumps, leaves a core with every thread's stack for
 * diagnosis. The limit is TEST_WATCHDOG_TIMEOUT seconds, overridable with the
 * OPENSSL_TEST_TIMEOUT environment variable; a value of 0 or less disables it.
 *
 * The default must exceed the slowest legitimate testutil program on the
 * slowest supported target (app-based recipes have their own main() and are
 * not covered here). Under emulated hppa the slowest such program runs well
 * under ten minutes, so thirty minutes leaves ample margin.
 */
#define TEST_WATCHDOG_TIMEOUT 1800

#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <signal.h>

/*
 * The message is prepared at arm time (with the actual limit) so that the
 * signal handler only has to call write(), which is async-signal-safe;
 * snprintf() is not.
 */
static char watchdog_msg[128];
static size_t watchdog_msg_len;

static void test_watchdog_expired(int sig)
{
    (void)sig;
    if (write(STDERR_FILENO, watchdog_msg, watchdog_msg_len) < 0) {
    }
    abort();
}

static void test_watchdog_start(unsigned int timeout)
{
    int n = snprintf(watchdog_msg, sizeof(watchdog_msg),
        "\n#  test watchdog: exceeded time limit of %u seconds, aborting\n",
        timeout);

    if (n < 0)
        n = 0;
    else if ((size_t)n >= sizeof(watchdog_msg))
        n = sizeof(watchdog_msg) - 1;
    watchdog_msg_len = (size_t)n;

    signal(SIGALRM, test_watchdog_expired);
    alarm(timeout);
}
#else
#include <stdint.h>
#include <windows.h>

static DWORD WINAPI test_watchdog_thread(LPVOID arg)
{
    unsigned int timeout = (unsigned int)(uintptr_t)arg;

    Sleep((DWORD)timeout * 1000);
    fprintf(stderr,
        "\n#  test watchdog: exceeded time limit of %u seconds, aborting\n",
        timeout);
    fflush(stderr);
    abort();
    return 0;
}

static void test_watchdog_start(unsigned int timeout)
{
    CreateThread(NULL, 0, test_watchdog_thread,
        (LPVOID)(uintptr_t)timeout, 0, NULL);
}
#endif /* !defined(OPENSSL_SYS_WINDOWS) */

static void setup_test_watchdog(void)
{
    long timeout = TEST_WATCHDOG_TIMEOUT;
    const char *e = getenv("OPENSSL_TEST_TIMEOUT");

    if (e != NULL && *e != '\0')
        timeout = strtol(e, NULL, 10);
    if (timeout <= 0)
        return;
    if ((unsigned long)timeout > UINT_MAX)
        timeout = UINT_MAX;
    test_watchdog_start((unsigned int)timeout);
}

/*
 * At some point we should consider looking at this function with a view to
 * moving most/all of this into onfree handlers in OSSL_LIB_CTX.
 */

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    int setup_res;
    int gi_ret;

    if (mfail_install(0) < 0) {
        test_printf_stderr("MFAIL installation failed - aborting\n");
        return ret;
    }

    gi_ret = global_init();

    test_open_streams();

    setup_test_watchdog();

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
     * when running our tests using valgrind in order to test the
     * suppression file which we will ship with the distribution. We
     * set the OSSL_USE_VALGRIND environment variable for this
     * purpose, but we only want to dodge cleanup when running under
     * valgrind, *and* that environment variable is set. If you run
     * this under valgrind without that environment variable set, it
     * will still call OPENSSL_cleanup normally.
     */
    if (RUNNING_ON_VALGRIND && getenv("OSSL_USE_VALGRIND") != NULL)
        return ret;
#endif /* defined(OPENSSL_VALGRIND_H_INCLUDED) && defined(RUNNING_ON_VALGRIND) */
    OPENSSL_cleanup();
    return ret;
}
