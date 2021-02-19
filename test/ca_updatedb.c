/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../apps/include/ca.h"
#include "../apps/include/ca_logic.h"
#include "../apps/include/apps.h"
#include "../apps/include/apps_extracted.h"
#include "testutil.h"

char *default_config_file = NULL;

int setup_tests(void)
{
    CA_DB *db = NULL;
    BIO *channel;
    time_t *testdateutc = NULL;
    int rv;
    int argc = test_get_argument_count();

    if (argc != 2) {
        fprintf(stderr, "Usage: ca_updatedb dbfile testdate\n");
        fprintf(stderr, "       testdate format: ASN1-String\n");
        return 0;
    }

    char *testdate = test_get_argument(1);
    testdateutc = asn1_string_to_time_t(testdate);
    if (testdateutc == NULL) {
        fprintf(stderr, "Error: testdate '%s' is invalid\n", testdate);
        return 0;
    }

    channel = BIO_push(BIO_new(BIO_f_prefix()), dup_bio_err(FORMAT_TEXT));
    bio_err = dup_bio_out(FORMAT_TEXT);

    default_config_file = CONF_get1_default_config_file();
    if (default_config_file == NULL) {
        BIO_free_all(bio_err);
        BIO_free_all(channel);
        free(testdateutc);
        fprintf(stderr, "Error: could not get default config file\n");
        return 0;
    }

    char *indexfile = test_get_argument(0);
    db = load_index(indexfile, NULL);
    if (db == NULL) {
        fprintf(stderr, "Error: dbfile '%s' is not readable\n", indexfile);
        free(indexfile);
        return 0;
    }

    rv = do_updatedb(db, testdateutc);

    if (rv > 0) {
        if (!save_index(indexfile, "new", db))
            goto end;

        if (!rotate_index(indexfile, "new", "old"))
            goto end;
    }
end:
    free(default_config_file);
    free_index(db);
    free(testdateutc);
    // produces a segfault...
    //BIO_free_all(bio_err);
    BIO_free_all(channel);
    return 1;
} 
