/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//#include "ca.h"
//#include "apps_config.h"
#include "apps_os_wrapper.h"
#include "testutil.h"
//#include "crypto/asn1.h"
#include <string.h>
#include <errno.h>

#define binname "apps_internals_test"

char *default_config_file = NULL;

static int test_app_rename(void)
{
    size_t argc = test_get_argument_count();

    if (argc != 3) {
        TEST_error("Usage: %s: app_rename srcfile dstfile\n", binname);
        return 0;
    }
    if (app_rename(test_get_argument(1), test_get_argument(2)) == 0) {
        return 1;
    }
    TEST_info("got error on rename: '%s'\n", strerror(errno));

    return 0;
}
//int test_do_updatedb(void)
//{
//    CA_DB *db = NULL;
//    time_t testdateutc;
//    int rv;
//    size_t argc = test_get_argument_count();
//    BIO *bio_tmp;
//
//    if (argc != 3) {
//        TEST_error("Usage: %s: do_updatedb dbfile testdate\n", binname);
//        TEST_error("       testdate format: ASN1-String\n");
//        return 0;
//    }
//
//    char *testdate = test_get_argument(2);
//    testdateutc = asn1_string_to_time_t(testdate);
//    if (testdateutc < 0) {
//        fprintf(stderr, "Error: testdate '%s' is invalid\n", testdate);
//        return 0;
//    }
//
//    char *indexfile = test_get_argument(1);
//    db = load_index(indexfile, NULL);
//    if (db == NULL) {
//        fprintf(stderr, "Error: dbfile '%s' is not readable\n", indexfile);
//        free(indexfile);
//        return 0;
//    }
//
//    bio_tmp = bio_err;
//    bio_err = bio_out;
//    rv = do_updatedb(db, &testdateutc);
//    bio_err = bio_tmp;
//
//    if (rv > 0) {
//        if (!save_index(indexfile, "new", db))
//            goto end;
//
//        if (!rotate_index(indexfile, "new", "old"))
//            goto end;
//    }
//end:
//    free_index(db);
//    return 1;
//} 

int setup_tests(void)
{
    char *command = test_get_argument(0);

    if (strcmp(command, "app_rename") == 0)
        return test_app_rename();
    
    TEST_error("%s: command '%s' is not supported for testing\n", binname, command);
    return 0;
}

