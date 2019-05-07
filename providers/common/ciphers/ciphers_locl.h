
/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/aes.h>
#include <openssl/modes.h>
#include "internal/cryptlib.h"

typedef struct prov_aes_cipher_st PROV_AES_CIPHER;

typedef struct prov_aes_key_st {
    union {
        OSSL_UNION_ALIGN;
        AES_KEY ks;
    } ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;

    /* Platform specific data */
    union {
        int dummy;
#if defined(OPENSSL_CPUID_OBJ) && defined(__s390__)
        struct {
            union {
                OSSL_UNION_ALIGN;
                /*-
                 * KM-AES parameter block - begin
                 * (see z/Architecture Principles of Operation >= SA22-7832-06)
                 */
                struct {
                    unsigned char k[32];
                } km;
                /* KM-AES parameter block - end */
                /*-
                 * KMO-AES/KMF-AES parameter block - begin
                 * (see z/Architecture Principles of Operation >= SA22-7832-08)
                 */
                struct {
                    unsigned char cv[16];
                    unsigned char k[32];
                } kmo_kmf;
                /* KMO-AES/KMF-AES parameter block - end */
            } param;
            unsigned int fc;
            int res;
        } s390x;
#endif /* defined(OPENSSL_CPUID_OBJ) && defined(__s390__) */
    } plat;

    /* The cipher functions we are going to use */
    const PROV_AES_CIPHER *ciph;

    /* The mode that we are using */
    int mode;

    /* Set to 1 if we are encrypting or 0 otherwise */
    int enc;

    unsigned char iv[AES_BLOCK_SIZE];

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    size_t num;

    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[AES_BLOCK_SIZE];

    /* Number of bytes in buf */
    size_t bufsz;

    uint64_t flags;

    size_t keylen;

    /* Whether padding should be used or not */
    unsigned int pad : 1;
} PROV_AES_KEY;

struct prov_aes_cipher_st {
  int (*init)(PROV_AES_KEY *dat, const uint8_t *key, size_t keylen);
  int (*cipher)(PROV_AES_KEY *dat, uint8_t *out, const uint8_t *in,
                size_t inl);
};

const PROV_AES_CIPHER *PROV_AES_CIPHER_ecb(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_cbc(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_ofb(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_cfb(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_cfb1(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_cfb8(size_t keylen);
const PROV_AES_CIPHER *PROV_AES_CIPHER_ctr(size_t keylen);

size_t fillblock(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
int trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
void padblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize);
