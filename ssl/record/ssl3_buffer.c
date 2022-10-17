/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_local.h"
#include "record_local.h"

void SSL3_BUFFER_set_data(SSL3_BUFFER *b, const unsigned char *d, size_t n)
{
    if (d != NULL)
        memcpy(b->buf, d, n);
    b->left = n;
    b->offset = 0;
}

/*
 * Clear the contents of an SSL3_BUFFER but retain any memory allocated. Also
 * retains the default_len setting
 */
void SSL3_BUFFER_clear(SSL3_BUFFER *b)
{
    b->offset = 0;
    b->left = 0;
}

void SSL3_BUFFER_release(SSL3_BUFFER *b)
{
    OPENSSL_free(b->buf);
    b->buf = NULL;
}
