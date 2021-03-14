/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_CONFIG_H
#define OSSL_APPS_APPS_CONFIG_H

extern char *default_config_file; /* may be "" */
CONF *app_load_config_bio(BIO *in, const char *filename);
#define app_load_config(filename) app_load_config_internal(filename, 0)
#define app_load_config_quiet(filename) app_load_config_internal(filename, 1)
CONF *app_load_config_internal(const char *filename, int quiet);
CONF *app_load_config_verbose(const char *filename, int verbose);

#endif                          /* ! OSSL_APPS_APPS_CONFIG_H */
