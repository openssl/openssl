/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Common logic used by s_client, s_server, and s_time */

#include "s_apps.h"

void print_secure_renegotiation_notes(BIO* bio, SSL* s) {
    if (TLS_VERSION_ALLOWS_RENEGOTIATION(SSL_version(s))) {
        BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
                   SSL_get_secure_renegotiation_support(s) ? "" : " NOT");
    } else {
        BIO_printf(bio, "Renegotiation does not happen in this TLS version.\n");
    }
}
