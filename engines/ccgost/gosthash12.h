/**********************************************************************
 *   gosthash12.h                                                     *
 *   Copyright (c) 2013 Demos Ltd., Dmitry L. Olshansky               *
 *                      dolshansky@demos.ru                           *
 *                                                                    *
 *       Implementation of GOST R 34.11-2012 hash function.           *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/ 
#ifndef GOSTHASH12_H
#define GOSTHASH12_H

typedef struct gost12_hash_ctx {
    int len;
    int left;
    unsigned char H[64];
    unsigned char N[64];
    unsigned char S[64];
    unsigned char remainder[64];
} gost12_hash_ctx;

int start_hash12(gost12_hash_ctx *ctx, size_t length);
int hash_block12(gost12_hash_ctx *ctx, const unsigned char *block, size_t length);
int finish_hash12(gost12_hash_ctx *ctx, char unsigned *hashval);

#endif

