/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APP_PROVIDER_H
#define OSSL_APPS_APP_PROVIDER_H

int app_provider_load(OSSL_LIB_CTX *libctx, const char *provider_name);
void app_providers_cleanup(void);

#endif                          /* ! OSSL_APPS_APPS_EXTRACTED_H */
