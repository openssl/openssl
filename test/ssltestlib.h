/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSLTESTLIB_H
# define HEADER_SSLTESTLIB_H

# include <openssl/ssl.h>

int create_ssl_ctx_pair(const SSL_METHOD *sm, const SSL_METHOD *cm,
                        SSL_CTX **sctx, SSL_CTX **cctx, char *certfile,
                        char *privkeyfile);
int create_ssl_connection(SSL_CTX *serverctx, SSL_CTX *clientctx, SSL **sssl,
                          SSL **cssl, BIO *s_to_c_fbio, BIO *c_to_s_fbio);

#endif /* HEADER_SSLTESTLIB_H */
