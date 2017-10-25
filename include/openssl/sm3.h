/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 [Ribose Inc.](https://www.ribose.com). All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM3_H
# define HEADER_SM3_H

# include <openssl/opensslconf.h>

# ifdef OPENSSL_NO_SM3
#  error SM3 is disabled.
# endif

# ifdef  __cplusplus
extern "C" {
# endif

#define SM3_DIGEST_LENGTH 32
#define SM3_WORD unsigned int

# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
   SM3_WORD A, B, C, D, E, F, G, H;
   SM3_WORD Nl, Nh;
   SM3_WORD data[SM3_LBLOCK];
   unsigned int num;
} SM3_CTX;

int SM3_Init(SM3_CTX *c);
int SM3_Update(SM3_CTX *c, const void *data, size_t len);
int SM3_Final(unsigned char *md, SM3_CTX *c);
void SM3_Transform(SM3_CTX *c, const unsigned char *data);
unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md);

# ifdef  __cplusplus
}
# endif

#endif
