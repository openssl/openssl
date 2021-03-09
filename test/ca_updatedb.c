/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../apps/include/ca.h"
#include "../apps/include/apps_extracted.h"
#include "testutil.h"
#include "crypto/asn1.h"

char *default_config_file = NULL;

int setup_tests(void)
{
    CA_DB *db = NULL;
    time_t testdateutc;
    int rv;
    int argc = test_get_argument_count();
    BIO *bio_tmp;

    if (argc != 2) {
        fprintf(stderr, "Usage: ca_updatedb dbfile testdate\n");
        fprintf(stderr, "       testdate format: ASN1-String\n");
        return 0;
    }

    char *testdate = test_get_argument(1);
    testdateutc = asn1_string_to_time_t(testdate);
    if (testdateutc < 0) {
        fprintf(stderr, "Error: testdate '%s' is invalid\n", testdate);
        return 0;
    }

    char *indexfile = test_get_argument(0);
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
