/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PEM_INT_H
# define HEADER_PEM_INT_H

# include <openssl/pem.h>

/* Found in crypto/pem/pvkfmt.c */
int ossl_do_blob_header(const unsigned char **in, unsigned int length,
                        unsigned int *pmagic, unsigned int *pbitlen,
                        int *pisdss, int *pispub);
int ossl_do_PVK_header(const unsigned char **in, unsigned int length,
                       int skip_magic,
                       unsigned int *psaltlen, unsigned int *pkeylen);

#endif
