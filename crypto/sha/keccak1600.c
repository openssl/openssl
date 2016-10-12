/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>
#include <string.h>
#include <assert.h>

#define ROL64(a, offset) ((offset) ? (((a) << offset) | ((a) >> (64-offset))) \
                                   : a)

static void Theta(uint64_t A[5][5])
{
    uint64_t C[5], D[5];
    size_t y;

    C[0] = A[0][0] ^ A[1][0] ^ A[2][0] ^ A[3][0] ^ A[4][0];
    C[1] = A[0][1] ^ A[1][1] ^ A[2][1] ^ A[3][1] ^ A[4][1];
    C[2] = A[0][2] ^ A[1][2] ^ A[2][2] ^ A[3][2] ^ A[4][2];
    C[3] = A[0][3] ^ A[1][3] ^ A[2][3] ^ A[3][3] ^ A[4][3];
    C[4] = A[0][4] ^ A[1][4] ^ A[2][4] ^ A[3][4] ^ A[4][4];

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
}

static void Rho(uint64_t A[5][5])
{
    static const unsigned char rhotates[5][5] = {
        {  0,  1, 62, 28, 27 },
        { 36, 44,  6, 55, 20 },
        {  3, 10, 43, 25, 39 },
        { 41, 45, 15, 21,  8 },
        { 18,  2, 61, 56, 14 }
    };
    size_t y;

    for (y = 0; y < 5; y++) {
        A[y][0] = ROL64(A[y][0], rhotates[y][0]);
        A[y][1] = ROL64(A[y][1], rhotates[y][1]);
        A[y][2] = ROL64(A[y][2], rhotates[y][2]);
        A[y][3] = ROL64(A[y][3], rhotates[y][3]);
        A[y][4] = ROL64(A[y][4], rhotates[y][4]);
    }
}

static void Pi(uint64_t A[5][5])
{
    uint64_t T[5][5];

    /*
     * T = A
     * A[y][x] = T[x][(3*y+x)%5]
     */
    memcpy(T, A, sizeof(T));

    A[0][0] = T[0][0];
    A[0][1] = T[1][1];
    A[0][2] = T[2][2];
    A[0][3] = T[3][3];
    A[0][4] = T[4][4];

    A[1][0] = T[0][3];
    A[1][1] = T[1][4];
    A[1][2] = T[2][0];
    A[1][3] = T[3][1];
    A[1][4] = T[4][2];

    A[2][0] = T[0][1];
    A[2][1] = T[1][2];
    A[2][2] = T[2][3];
    A[2][3] = T[3][4];
    A[2][4] = T[4][0];

    A[3][0] = T[0][4];
    A[3][1] = T[1][0];
    A[3][2] = T[2][1];
    A[3][3] = T[3][2];
    A[3][4] = T[4][3];

    A[4][0] = T[0][2];
    A[4][1] = T[1][3];
    A[4][2] = T[2][4];
    A[4][3] = T[3][0];
    A[4][4] = T[4][1];
}

static void Chi(uint64_t A[5][5])
{
    uint64_t C[5];
    size_t y;

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
}

static void Iota(uint64_t A[5][5], size_t i)
{
    static const uint64_t iotas[] = {
        0x0000000000000001U, 0x0000000000008082U, 0x800000000000808aU,
        0x8000000080008000U, 0x000000000000808bU, 0x0000000080000001U,
        0x8000000080008081U, 0x8000000000008009U, 0x000000000000008aU,
        0x0000000000000088U, 0x0000000080008009U, 0x000000008000000aU,
        0x000000008000808bU, 0x800000000000008bU, 0x8000000000008089U,
        0x8000000000008003U, 0x8000000000008002U, 0x8000000000000080U,
        0x000000000000800aU, 0x800000008000000aU, 0x8000000080008081U,
        0x8000000000008080U, 0x0000000080000001U, 0x8000000080008008U
    };

    assert(i < (sizeof(iotas) / sizeof(iotas[0])));
    A[0][0] ^= iotas[i];
}

void KeccakF1600(uint64_t A[5][5])
{
    size_t i;

    for (i = 0; i < 24; i++) {
        Theta(A);
        Rho(A);
        Pi(A);
        Chi(A);
        Iota(A, i);
    }
}

/*
 * SHA3_absorb can be called multiple times, but at each invocation
 * |len| is expected to be divisible by |r|, effectively the blocksize.
 * Latter is commonly (1600 - 256*n)/8, e.g. 168, 136, 104, 72, but can
 * also be (1600 - 448)/8 = 144. This also means that message padding is
 * caller's reponsibility.
 */
void SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                 size_t r)
{
    uint64_t *A_flat = (uint64_t *)A;
    size_t i, w = r / 8;

    while (len >= r) {
        for (i = 0; i < w; i++) {
            A_flat[i] ^= (uint64_t)inp[0]       | (uint64_t)inp[1] << 8  |
                         (uint64_t)inp[2] << 16 | (uint64_t)inp[3] << 24 |
                         (uint64_t)inp[4] << 32 | (uint64_t)inp[5] << 40 |
                         (uint64_t)inp[6] << 48 | (uint64_t)inp[7] << 56;
            inp += 8;
        }
        KeccakF1600(A);
        len -= r;
    }
    assert(len == 0);
}

/*
 * SHA3_squeeze is called once at the end to generate |out| of |len|
 * bytes.
 */
void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r)
{
    uint64_t *A_flat = (uint64_t *)A;
    size_t i, rem, w = r / 8;

    while (len >= r) {
        for (i = 0; i < w; i++) {
            uint64_t Ai = A_flat[i];

            out[0] = (unsigned char)(Ai);
            out[1] = (unsigned char)(Ai >> 8);
            out[2] = (unsigned char)(Ai >> 16);
            out[3] = (unsigned char)(Ai >> 24);
            out[4] = (unsigned char)(Ai >> 32);
            out[5] = (unsigned char)(Ai >> 40);
            out[6] = (unsigned char)(Ai >> 48);
            out[7] = (unsigned char)(Ai >> 56);
            out += 8;
        }
        len -= r;
        if (len)
            KeccakF1600(A);
    }

    rem = len % 8;
    len /= 8;

    for (i = 0; i < len; i++) {
        uint64_t Ai = A_flat[i];

        out[0] = (unsigned char)(Ai);
        out[1] = (unsigned char)(Ai >> 8);
        out[2] = (unsigned char)(Ai >> 16);
        out[3] = (unsigned char)(Ai >> 24);
        out[4] = (unsigned char)(Ai >> 32);
        out[5] = (unsigned char)(Ai >> 40);
        out[6] = (unsigned char)(Ai >> 48);
        out[7] = (unsigned char)(Ai >> 56);
        out += 8;
    }

    if (rem) {
        uint64_t Ai = A_flat[i];

        for (i = 0; i < rem; i++) {
            *out++ = (unsigned char)Ai;
            Ai >>= 8;
        }
    }
}

#ifdef SELFTEST
/*
 * Post-padding one-shot implementations would look as following:
 *
 * SHA3_224     SHA3_sponge(inp, len, out, 224/8, (1600-448)/8);
 * SHA3_256     SHA3_sponge(inp, len, out, 256/8, (1600-512)/8);
 * SHA3_384     SHA3_sponge(inp, len, out, 384/8, (1600-768)/8);
 * SHA3_512     SHA3_sponge(inp, len, out, 512/8, (1600-1024)/8);
 * SHAKE_128    SHA3_sponge(inp, len, out, d, (1600-256)/8);
 * SHAKE_256    SHA3_sponge(inp, len, out, d, (1600-512)/8);
 */

void SHA3_sponge(const unsigned char *inp, size_t len,
                 unsigned char *out, size_t d, size_t r)
{
    uint64_t A[5][5];

    memset(A, 0, sizeof(A));
    SHA3_absorb(A, inp, len, r);
    SHA3_squeeze(A, out, d, r);
}

# include <stdio.h>

int main()
{
    unsigned char test[168] = { '\xf3', '\x3' };
    unsigned char out[512];
    size_t i;

    /*
     * This is 5-bit SHAKE128 test from http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing
     */
    test[167] = '\x80';
    SHA3_sponge(test, sizeof(test), out, sizeof(out), sizeof(test));

    for (i = 0; i < sizeof(out);) {
        printf("%02X", out[i]);
        printf(++i % 16 && i != sizeof(out) ? " " : "\n");
    }
}
#endif
