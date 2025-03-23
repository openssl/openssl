/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "output.h"
#include "tu_local.h"

#ifdef OPENSSL_DO_MPROFILE

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>

#define BUF_SZ  512
extern void mprofile_start(void);
#endif

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    int setup_res;
#ifdef OPENSSL_DO_MPROFILE
    /*
     * We need to make mprofile part of libtestutil so we can
     * snoop calls to CRYPTO_malloc(), CRYPTO_free() and CRYPTO_realloc()
     * to libcrypto.a, because many tests use libcrypto.a
     */
    char annotation_buf[2][BUF_SZ];
    char *do_mprofile = getenv("DO_MPROFILE");
    char *file_name = getenv("MPROFILE_OUTF");
    int i, sn;

    if (do_mprofile != NULL) {
        /*
         * Tests may execute single binary with different arguments.  The
         * memory profiler (libmprofile) expects test to set MPROFILE_OUTF
         * environment variable to specify file where to store the result.
         * Such approach requires to update all test recopies. This can be done
         * later, step-by-step. To allow this step-by-step approach we derive
         * output file from arguments.
         *
         * Another option is to use strlcat(3) to concatenate all arguments
         * into single string. My preference is to for snprintf() and flip
         * two buffers as loop goes.
         */
        annotation_buf[0][0] = '\0';
        annotation_buf[1][0] = '\0';
        for (i = 0; i < argc && sn < BUF_SZ; i++) {
            if (i == 0)
                sn = snprintf(annotation_buf[i], BUF_SZ, "%s",
                              basename(argv[i]));
            else
                sn = snprintf(annotation_buf[i % 2], BUF_SZ, "%s %s",
                              annotation_buf[(i - 1) % 2], argv[i]);
        }
        setenv("MPROFILE_ANNOTATION", annotation_buf[(i - 1) % 2], 0);

        /*
         * Almost every test gets two instances of libmprofile:
         *     - libmprofile.so instance we get via LD_PRELOAD
         *         - libmprofile we get via static libtestutil library
         * Both instances are controlled via the identical env. variables
         * including MPROFILE_OUTF. To resolve conflict between dynamic and
         * static version of libmprofile we prepend a static_ prefix to
         * output data which come from libtestutil/mprofile.
         */
        snprintf(annotation_buf[0], BUF_SZ, "%s/testutil_%s",
                 dirname(file_name), basename(file_name));
        setenv("MPROFILE_OUTF", annotation_buf[0], 1);
        mprofile_start();
    }
#endif

    test_open_streams();

    if (!global_init()) {
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
    return ret;
}
