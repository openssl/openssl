/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/byteorder.h>
#include "internal/sha3.h"

static uint64_t ROL64(uint64_t val, int offset)
{
    return offset == 0 ? val : (val << offset) | (val >> (64 - offset));
}

static const unsigned char rhotates[5][5] = {
    { 0, 1, 62, 28, 27 },
    { 36, 44, 6, 55, 20 },
    { 3, 10, 43, 25, 39 },
    { 41, 45, 15, 21, 8 },
    { 18, 2, 61, 56, 14 }
};

static const uint64_t iotas[] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

static void KeccakP1600_12(uint64_t A[5][5])
{
    uint64_t C[5], D[5], T[5][5];
    size_t i, x, y;

    for (i = 12; i < 24; i++) {
        C[0] = A[0][0];
        C[1] = A[0][1];
        C[2] = A[0][2];
        C[3] = A[0][3];
        C[4] = A[0][4];

        for (y = 1; y < 5; y++) {
            C[0] ^= A[y][0];
            C[1] ^= A[y][1];
            C[2] ^= A[y][2];
            C[3] ^= A[y][3];
            C[4] ^= A[y][4];
        }

        D[0] = ROL64(C[1], 1) ^ C[4];
        D[1] = ROL64(C[2], 1) ^ C[0];
        D[2] = ROL64(C[3], 1) ^ C[1];
        D[3] = ROL64(C[4], 1) ^ C[2];
        D[4] = ROL64(C[0], 1) ^ C[3];

        for (y = 0; y < 5; y++) {
            A[y][0] ^= D[0];
            A[y][1] ^= D[1];
            A[y][2] ^= D[2];
            A[y][3] ^= D[3];
            A[y][4] ^= D[4];
        }

        memcpy(T, A, sizeof(T));
        for (y = 0; y < 5; y++)
            for (x = 0; x < 5; x++)
                A[y][x] = ROL64(T[x][(3 * y + x) % 5],
                    rhotates[x][(3 * y + x) % 5]);

        for (y = 0; y < 5; y++) {
            C[0] = A[y][0] ^ (~A[y][1] & A[y][2]);
            C[1] = A[y][1] ^ (~A[y][2] & A[y][3]);
            C[2] = A[y][2] ^ (~A[y][3] & A[y][4]);
            C[3] = A[y][3] ^ (~A[y][4] & A[y][0]);
            C[4] = A[y][4] ^ (~A[y][0] & A[y][1]);

            A[y][0] = C[0];
            A[y][1] = C[1];
            A[y][2] = C[2];
            A[y][3] = C[3];
            A[y][4] = C[4];
        }

        A[0][0] ^= iotas[i];
    }
}

size_t ossl_keccak1600_absorb_p12(uint64_t A[5][5],
    const unsigned char *inp, size_t len, size_t r)
{
    uint64_t *A_flat = (uint64_t *)A;
    size_t i, w = r / 8;

    assert(r < (25 * sizeof(A[0][0])) && (r % 8) == 0);

    while (len >= r) {
        for (i = 0; i < w; i++) {
            uint64_t Ai;

            inp = OPENSSL_load_u64_le(&Ai, inp);
            A_flat[i] ^= Ai;
        }
        KeccakP1600_12(A);
        len -= r;
    }

    return len;
}

void ossl_keccak1600_squeeze_p12(uint64_t A[5][5], unsigned char *out,
    size_t len, size_t r, int next)
{
    uint64_t *A_flat = (uint64_t *)A;
    size_t i, w = r / 8;

    assert(r < (25 * sizeof(A[0][0])) && (r % 8) == 0);

    while (len != 0) {
        if (next)
            KeccakP1600_12(A);
        next = 1;
        for (i = 0; i < w && len != 0; i++) {
            uint64_t Ai = A_flat[i];

            if (len < 8) {
                while (len-- > 0) {
                    *out++ = (unsigned char)Ai;
                    Ai >>= 8;
                }
                return;
            }

            out = OPENSSL_store_u64_le(out, Ai);
            len -= 8;
        }
    }
}
