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

#define	FNAME_BUF_SZ	512
extern void mprofile_start(void);
#endif

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    int setup_res;
#ifdef OPENSSL_DO_MPROFILE
    char file_name_buf[2][FNAME_BUF_SZ];
    char *do_mprofile = getenv("DO_MPROFILE");
    char *results_dir = getenv("MPROFILE_RESULTS");
    int i, sn;

    if (do_mprofile != NULL && results_dir != NULL) {
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
         file_name_buf[0][0] = '\0';
         file_name_buf[1][0] = '\0';
         for (i = 0; i < argc && sn < FNAME_BUF_SZ; i++) {
             if (i == 0)
                 sn = snprintf(file_name_buf[i], FNAME_BUF_SZ, "%s",
                     basename(argv[i]));
             else
                 sn = snprintf(file_name_buf[i % 2], FNAME_BUF_SZ, "%s__%s",
                 file_name_buf[(i - 1) % 2], basename(argv[i]));
         }

         if (i == argc && results_dir != NULL) {
             sn = snprintf(file_name_buf[i % 2], FNAME_BUF_SZ, "%s/%s.json",
                 results_dir, file_name_buf[(i - 1) % 2]);
             if (sn < FNAME_BUF_SZ) {
                 setenv("MPROFILE_OUTF", file_name_buf[i % 2], 1);
                 /*
                  * we are all set to run mprofile. mprofile is best effort,
                  * os if anything fails just give up. Perhaps we should
                  * report such failure.
                  */
                  mprofile_start();
             }
         }
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
