/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Core cryptographic operations, i.e. permutations of the sponge state.
 *
 * This file is based on LibAscon (CC0 1.0 license).
 * Original authors: see LibAscon AUTHORS.md file
 */

# include "crypto/ascon.h"
/* Linter warnings about #include "ascon_internal.h" being unused are WRONG.
 * If you do not include the header, the linker cannot find the references. */
# include "ascon_internal.h"


/* 12-round permutation starts here */
# define ROUND_CONSTANT_01 0xF0
# define ROUND_CONSTANT_02 0xE1
# define ROUND_CONSTANT_03 0xD2
# define ROUND_CONSTANT_04 0xC3

/* 8-round permutation starts here */
# define ROUND_CONSTANT_05 0xB4
# define ROUND_CONSTANT_06 0xA5

/* 6-round permutation starts here */
# define ROUND_CONSTANT_07 0x96
# define ROUND_CONSTANT_08 0x87
# define ROUND_CONSTANT_09 0x78
# define ROUND_CONSTANT_10 0x69
# define ROUND_CONSTANT_11 0x5A
# define ROUND_CONSTANT_12 0x4B

/** Bit-shift and rotation of a uint64_t to the right by n bits. */
# define ASCON_ROTR64(x, n) (((x) << (64U - (n)) ) | ((x) >> (n)))

/**
 * @internal
 * Performs one permutation round on the Ascon sponge for the given round
 * constant.
 *
 * Although this function is never used outside this file,
 * it is NOT marked as static, as it is generally inline in the functions
 * using it to increase the performance. Inlining static functions into
 * functions used outside this file leads to compilation errors:
 * "error: static function 'ascon_round' is used in an inline function with
 * external linkage `[-Werror,-Wstatic-in-inline]`".
 */
ASCON_INLINE void
ascon_round(ascon_sponge_t* sponge,
            const uint_fast8_t round_const)
{
    /* addition of round constant */
    sponge->x2 ^= round_const;
    /* substitution layer */
    sponge->x0 ^= sponge->x4;
    sponge->x4 ^= sponge->x3;
    sponge->x2 ^= sponge->x1;
    /* start of keccak s-box */
    const ascon_sponge_t temp = {
            .x0 = (~sponge->x0) & sponge->x1,
            .x1 = (~sponge->x1) & sponge->x2,
            .x2 = (~sponge->x2) & sponge->x3,
            .x3 = (~sponge->x3) & sponge->x4,
            .x4 = (~sponge->x4) & sponge->x0,
    };
    sponge->x0 ^= temp.x1;
    sponge->x1 ^= temp.x2;
    sponge->x2 ^= temp.x3;
    sponge->x3 ^= temp.x4;
    sponge->x4 ^= temp.x0;
    /* end of keccak s-box */
    sponge->x1 ^= sponge->x0;
    sponge->x0 ^= sponge->x4;
    sponge->x3 ^= sponge->x2;
    sponge->x2 = ~sponge->x2;
    /* linear diffusion layer */
    sponge->x0 ^= ASCON_ROTR64(sponge->x0, 19) ^ ASCON_ROTR64(sponge->x0, 28);
    sponge->x1 ^= ASCON_ROTR64(sponge->x1, 61) ^ ASCON_ROTR64(sponge->x1, 39);
    sponge->x2 ^= ASCON_ROTR64(sponge->x2, 1) ^ ASCON_ROTR64(sponge->x2, 6);
    sponge->x3 ^= ASCON_ROTR64(sponge->x3, 10) ^ ASCON_ROTR64(sponge->x3, 17);
    sponge->x4 ^= ASCON_ROTR64(sponge->x4, 7) ^ ASCON_ROTR64(sponge->x4, 41);
}

ASCON_INLINE void
ascon_permutation_12(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_01);
    ascon_round(sponge, ROUND_CONSTANT_02);
    ascon_round(sponge, ROUND_CONSTANT_03);
    ascon_round(sponge, ROUND_CONSTANT_04);
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void
ascon_permutation_8(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void
ascon_permutation_6(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

