/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

int main()
{
    char *p = NULL;
    char bytes[sizeof(p)];

    memset(bytes, 0, sizeof bytes);
    return memcmp(&p, bytes, sizeof(bytes)) == 0 ? 0 : 1;
}
