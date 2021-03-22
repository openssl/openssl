/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "ca.h"
#include "apps_config.h"
#include "testutil.h"
#include "crypto/asn1.h"

#define binname "ca_internals_test"

char *default_config_file = NULL;

static int test_do_updatedb(void)
{
    CA_DB *db = NULL;
    time_t testdateutc;
    int rv;
    size_t argc = test_get_argument_count();
    BIO *bio_tmp;

    if (argc != 3) {
        TEST_error("Usage: %s: do_updatedb dbfile testdate\n", binname);
        TEST_error("       testdate format: ASN1-String\n");
        return 0;
    }

    char *testdate = test_get_argument(2);
    testdateutc = asn1_string_to_time_t(testdate);
    if (testdateutc < 0) {
        fprintf(stderr, "Error: testdate '%s' is invalid\n", testdate);
        return 0;
    }

    char *indexfile = test_get_argument(1);
    db = load_index(indexfile, NULL);
    if (db == NULL) {
        fprintf(stderr, "Error: dbfile '%s' is not readable\n", indexfile);
        free(indexfile);
        return 0;
    }

    bio_tmp = bio_err;
    bio_err = bio_out;
    rv = do_updatedb(db, &testdateutc);
    bio_err = bio_tmp;

    if (rv > 0) {
        if (!save_index(indexfile, "new", db))
            goto end;

        if (!rotate_index(indexfile, "new", "old"))
            goto end;
    }
end:
    free_index(db);
    return 1;
} 

int setup_tests(void)
{
    char *command = test_get_argument(0);

    if (strcmp(command, "do_updatedb") == 0)
        return test_do_updatedb();
    
    TEST_error("%s: command '%s' is not supported for testing\n", binname, command);
    return 0;
}

