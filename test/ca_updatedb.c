/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef OPENSSL_SYS_UNIX
# include <unistd.h>
#endif
#include "../apps/include/ca.h"
#include "../apps/include/ca_logic.h"
#include "../apps/include/apps.h"

/* tweaks needed due to missing unistd.h on Windows */
#ifdef _WIN32
# define access _access
#endif

char *default_config_file = NULL;

int main(int argc, char *argv[])
{
    CA_DB *db = NULL;
    int r;
    time_t *testdate;
    BIO *channel;

    channel = BIO_push(BIO_new(BIO_f_prefix()), dup_bio_err(FORMAT_TEXT));
    bio_out = dup_bio_out(FORMAT_TEXT);
    bio_err = dup_bio_err(FORMAT_TEXT);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s indexfile testdate\n", argv[0]);
        fprintf(stderr, "       testdate format: YYYY-MM-DDThh:mm\n");
	exit(EXIT_FAILURE);
    }
    if (access(argv[1], F_OK) != 0) {
        fprintf(stderr, "Error: dbfile '%s' is not readable\n", argv[1]);
	exit(EXIT_FAILURE);
    }

    testdate = app_malloc(sizeof(time_t), "testdate");
    *testdate = iso8601_utc_to_time_t(argv[2]);
    if (*testdate == 0) {
        free(testdate);
        fprintf(stderr, "Error: testdate '%s' is invalid\n", argv[2]);
	exit(EXIT_FAILURE);
    }

    default_config_file = CONF_get1_default_config_file();
    if (default_config_file == NULL) {
        free(testdate);
        fprintf(stderr, "Error: could not get default config file\n");
	exit(EXIT_FAILURE);
    }

    db = load_index(argv[1], NULL);

    r = do_updatedb(db, testdate);

    if (r == -1)
	exit(EXIT_FAILURE);

    free(default_config_file);
    free_index(db);
    free(testdate);
    BIO_free_all(channel);
    exit(EXIT_SUCCESS);
}
