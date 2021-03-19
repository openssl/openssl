/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_PASSWD_H
#define OSSL_APPS_APPS_PASSWD_H

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2);
char *get_passwd(const char *pass, const char *desc);

#endif                          /* ! OSSL_APPS_APPS_PASSWD_H */
