/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_OPTS_H
#define OSSL_APPS_APPS_OPTS_H

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);
int set_nameopt(const char *arg);
unsigned long get_nameopt(void);

#endif                          /* ! OSSL_APPS_APPS_EXTRACTED_H */
