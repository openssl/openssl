/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CAESAR_H
# define HEADER_CAESAR_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CAESAR
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

typedef struct caesar_key_st {
    unsigned char len;
    unsigned char data[256];
} CAESAR_KEY;

const char *CAESAR_options(void);
void CAESAR_set_key(CAESAR_KEY *key, int len, const unsigned char *data);
void CAESAR(CAESAR_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

# ifdef  __cplusplus
}
# endif
# endif

#endif
