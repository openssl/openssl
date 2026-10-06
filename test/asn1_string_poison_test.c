/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file asn1_string_poison_test.c
 * Checks that the NUL terminator libcrypto writes after ASN1_STRING data is
 * inaccessible under AddressSanitizer, MemorySanitizer and Valgrind. Run
 * with no argument the program reads the terminator with strlen() and is
 * expected to be killed by the sanitizer; run with "counted" it reads only
 * the counted bytes and is expected to exit successfully. Without a
 * sanitizer the strlen() run exits with failure itself; with one, surviving
 * the strlen() exits successfully, which the recipe reports as a failure.
 * Under Valgrind the process survives the strlen() and memcheck reports the
 * read. When OSSL_VALGRIND_CT is set the test framework runs memcheck with
 * --error-exitcode=1, and the program exits successfully after the strlen()
 * the same way, leaving the exit status to memcheck; under any other
 * Valgrind wrapper it exits with failure.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>

#include "testutil.h"

#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
#define HAVE_SANITIZER 1
#endif
#endif /* defined(__has_feature) */
#if defined(__SANITIZE_ADDRESS__) && !defined(HAVE_SANITIZER)
#define HAVE_SANITIZER 1
#endif
#if defined __has_include
/* Any compiler you're going to run valgrind on has this */
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#endif
#endif /* defined(__has_include) */

/* DER UTF8String "hello" */
static const unsigned char der[] = { 0x0c, 0x05, 'h', 'e', 'l', 'l', 'o' };

/**
 * @brief Report whether a checker decides this run's exit status.
 * That is a sanitizer, or memcheck run by the test framework with
 * --error-exitcode=1 (OSSL_VALGRIND_CT).
 * @returns 1 when the checker sets the exit status, 0 otherwise
 */
static int checker_sets_exit_status(void)
{
#if defined(HAVE_SANITIZER)
    return 1;
#else
#if defined(RUNNING_ON_VALGRIND)
    if (RUNNING_ON_VALGRIND && getenv("OSSL_VALGRIND_CT") != NULL)
        return 1;
#endif
    return 0;
#endif /* defined(HAVE_SANITIZER) */
}

/*
 * A plain main() rather than the test framework's: the failing run is
 * expected to die inside the sanitizer, which the framework would report
 * as a crash.
 */
int main(int argc, char *argv[])
{
    const unsigned char *p = der;
    ASN1_UTF8STRING *str = d2i_ASN1_UTF8STRING(NULL, &p, sizeof(der));
    const unsigned char *data;
    volatile size_t sink;
    int exitcode = EXIT_FAILURE;

    if (!TEST_ptr(str)
        || !TEST_size_t_eq(ASN1_STRING_get_length(str), 5))
        goto end;
    data = ASN1_STRING_get0_data(str);

    if (argc > 1 && strcmp(argv[1], "counted") == 0) {
        /* Counted access never touches the terminator. */
        if (TEST_mem_eq(data, ASN1_STRING_get_length(str), "hello", 5))
            exitcode = EXIT_SUCCESS;
        goto end;
    }

    /*
     * Reads the terminator; a sanitizer kills the process here, memcheck
     * reports the read and lets the process continue.
     */
    sink = strlen((const char *)data);
    (void)sink;
    if (checker_sets_exit_status()) {
        /*
         * Reached under a sanitizer only when it did not report the read.
         * The recipe expects this run to fail: under a sanitizer a
         * successful exit is that failure; under memcheck the exit status
         * is replaced by --error-exitcode when the read was reported.
         */
        TEST_note("strlen() on ASN1_STRING data survived");
        exitcode = EXIT_SUCCESS;
    }

end:
    ASN1_UTF8STRING_free(str);
    return exitcode;
}
