/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_CA_H
#define OSSL_APPS_CA_H

#include "openssl/txt_db.h"
# ifndef OPENSSL_NO_POSIX_IO
#  include <fcntl.h>
#  include <sys/stat.h>
# endif

typedef struct db_attr_st {
    int unique_subject;
} DB_ATTR;

typedef struct ca_db_st {
    DB_ATTR attributes;
    TXT_DB *db;
    char *dbfname;
# ifndef OPENSSL_NO_POSIX_IO
    struct stat dbst;
# endif
} CA_DB;

#endif                          /* ! OSSL_APPS_CA_H */
