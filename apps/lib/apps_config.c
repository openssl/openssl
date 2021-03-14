/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps_config.h"

CONF *app_load_config_bio(BIO *in, const char *filename)
{
    long errorline = -1;
    CONF *conf;
    int i;

    conf = NCONF_new_ex(app_libctx, NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    if (i > 0)
        return conf;

    if (errorline <= 0) {
        BIO_printf(bio_err, "%s: Can't load ", opt_getprog());
    } else {
        BIO_printf(bio_err, "%s: Error on line %ld of ", opt_getprog(),
                   errorline);
    }
    if (filename != NULL)
        BIO_printf(bio_err, "config file \"%s\"\n", filename);
    else
        BIO_printf(bio_err, "config input");

    NCONF_free(conf);
    return NULL;
}

CONF *app_load_config_verbose(const char *filename, int verbose)
{
    if (verbose) {
        if (*filename == '\0')
            BIO_printf(bio_err, "No configuration used\n");
        else
            BIO_printf(bio_err, "Using configuration from %s\n", filename);
    }
    return app_load_config_internal(filename, 0);
}

CONF *app_load_config_internal(const char *filename, int quiet)
{
    BIO *in = NULL; /* leads to empty config in case filename == "" */
    CONF *conf;

    if (*filename != '\0'
        && (in = bio_open_default_(filename, 'r', FORMAT_TEXT, quiet)) == NULL)
        return NULL;
    conf = app_load_config_bio(in, filename);
    BIO_free(in);
    return conf;
}


