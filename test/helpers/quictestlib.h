/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <internal/quic_tserver.h>

typedef struct ossl_quic_fault OSSL_QUIC_FAULT;

int qtest_create_quic_objects(SSL_CTX *clientctx, char *certfile, char *keyfile,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              OSSL_QUIC_FAULT **fault);
int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl);
