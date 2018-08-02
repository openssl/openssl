/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 BaishanCloud. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ZUC_H
# define HEADER_ZUC_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>

# ifdef OPENSSL_NO_ZUC
#  error ZUC is disabled.
# endif

#define EVP_ZUC_KEY_SIZE 16

typedef struct ZUC_KEY_st {
    /* Linear Feedback Shift Register cells */
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;

    /* the outputs of BitReorganization */
    uint32_t X0, X1, X2, X3;

    /* non linear function F cells */
    uint32_t R1, R2;

    const uint8_t *k;
    uint8_t iv[16];

    /* keystream */
    uint8_t *keystream;
    uint32_t keystream_len;
    int L;

    int inited;
} ZUC_KEY;

void ZUC_init(ZUC_KEY *zk);
int ZUC_generate_keystream(ZUC_KEY *zk);
void ZUC_destroy_keystream(ZUC_KEY *zk);

#endif
