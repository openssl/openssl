/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_CA_LOGIC_H
#define OSSL_APPS_CA_LOGIC_H

/* tweaks needed for Windows */
#ifdef _WIN32
# define timezone _timezone
#endif

ASN1_TIME *asn1_string_to_ASN1_TIME(char *asn1_string);
time_t *asn1_string_to_time_t(char *asn1_string);

#endif                          /* ! OSSL_APPS_CA_LOGIC_H */
