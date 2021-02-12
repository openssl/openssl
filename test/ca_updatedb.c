/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <unistd.h>
#include "../apps/include/ca.h"
#include "../apps/include/ca_logic.h"
#include "apps.h"

char *default_config_file = NULL;

int main(int argc, char *argv[])
{
    CA_DB *db = NULL;
    int r;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s indexfile date\n", argv[0]);
	exit(EXIT_FAILURE);
    }
    if (access(argv[1], F_OK) != 0) {
        fprintf(stderr, "Error: dbfile '%s' is not readable\n", argv[1]);
	exit(EXIT_FAILURE);
    }

    default_config_file = CONF_get1_default_config_file();
    if (default_config_file == NULL) {
        fprintf(stderr, "Error: could not get default config file\n");
	exit(EXIT_FAILURE);
    }

    db = load_index(argv[1], NULL);

    r = do_updatedb(db, NULL);

    if (r == -1)
	exit(EXIT_FAILURE);

    printf("Marked %i entries as expired\n", r);
    exit(EXIT_SUCCESS);

    // /home/armin/work/apt-src/openssl-test/2017/ovpn-intermediate/index.txt
}
