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

CA_DB *load_index(const char *dbfile, DB_ATTR *dbattr);
int index_index(CA_DB *db);
int save_index(const char *dbfile, const char *suffix, CA_DB *db);
int rotate_index(const char *dbfile, const char *new_suffix,
                 const char *old_suffix);
void free_index(CA_DB *db);
# define index_name_cmp_noconst(a, b) \
        index_name_cmp((const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, a), \
        (const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, b))
int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b);

BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(const char *serialfile, const char *suffix, const BIGNUM *serial,
                ASN1_INTEGER **retai);
int rotate_serial(const char *serialfile, const char *new_suffix,
                  const char *old_suffix);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);

#endif                          /* ! OSSL_APPS_CA_H */
