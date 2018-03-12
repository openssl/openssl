/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

/******************************************************************************
 *
 * File: ntru_crypto_ntru_convert.h
 *
 * Contents: Definitions and declarations for conversion routines
 *           for NTRUEncrypt, including packing, unpacking and others.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_CONVERT_H
#define NTRU_CRYPTO_NTRU_CONVERT_H

#include "ntru_crypto.h"

/* function declarations */

/* ntru_bits_2_trits
 *
 * Each 3 bits in an array of octets is converted to 2 trits in an array
 * of trits.
 */

extern void
ntru_bits_2_trits(
    uint8_t const *octets, /*  in - pointer to array of octets */
    uint16_t num_trits,    /*  in - number of trits to produce */
    uint8_t *trits);       /* out - address for array of trits */

/* ntru_trits_2_bits
 *
 * Each 2 trits in an array of trits is converted to 3 bits, and the bits
 * are packed in an array of octets.  A multiple of 3 octets is output.
 * Any bits in the final octets not derived from trits are zero.
 *
 * Returns TRUE if all trits were valid.
 * Returns FALSE if invalid trits were found.
 */

extern bool
ntru_trits_2_bits(
    uint8_t const *trits, /*  in - pointer to array of trits */
    uint32_t num_trits,   /*  in - number of trits to convert */
    uint8_t *octets);     /* out - address for array of octets */

/* ntru_coeffs_mod4_2_octets
 *
 * Takes an array of coefficients mod 4 and packs the results into an
 * octet string.
 */

extern void
ntru_coeffs_mod4_2_octets(
    uint16_t num_coeffs,    /*  in - number of coefficients */
    uint16_t const *coeffs, /*  in - pointer to coefficients */
    uint8_t *octets);       /* out - address for octets */

/* ntru_trits_2_octet
 *
 * Packs 5 trits in an octet, where a trit is 0, 1, or 2 (-1).
 */

extern void
ntru_trits_2_octet(
    uint8_t const *trits, /*  in - pointer to trits */
    uint8_t *octet);      /* out - address for octet */

/* ntru_octet_2_trits
 *
 * Unpacks an octet to 5 trits, where a trit is 0, 1, or 2 (-1).
 */

extern void
ntru_octet_2_trits(
    uint8_t octet,   /*  in - octet to be unpacked */
    uint8_t *trits); /* out - address for trits */

/* ntru_indices_2_trits
 *
 * Converts a list of the nonzero indices of a polynomial into an array of
 * trits.
 */

extern void
ntru_indices_2_trits(
    uint16_t in_len,    /*  in - no. of indices */
    uint16_t const *in, /*  in - pointer to list of indices */
    bool plus1,         /*  in - if list is +1 coefficients */
    uint8_t *out);      /* out - address of output polynomial */

/* ntru_packed_trits_2_indices
 *
 * Unpacks an array of N trits and creates a list of array indices 
 * corresponding to trits = +1, and list of array indices corresponding to
 * trits = -1.
 */

extern void
ntru_packed_trits_2_indices(
    uint8_t const *in,         /*  in - pointer to packed-trit octets */
    uint16_t num_trits,        /*  in - no. of packed trits */
    uint16_t *indices_plus1,   /* out - address for indices of +1 trits */
    uint16_t *indices_minus1); /* out - address for indices of -1 trits */

/* ntru_indices_2_packed_trits
 *
 * Takes a list of array indices corresponding to elements whose values
 * are +1 or -1, and packs the N-element array of trits described by these
 * lists into octets, 5 trits per octet.
 */

extern void
ntru_indices_2_packed_trits(
    uint16_t const *indices, /*  in - pointer to indices */
    uint16_t num_plus1,      /*  in - no. of indices for +1 trits */
    uint16_t num_minus1,     /*  in - no. of indices for -1 trits */
    uint16_t num_trits,      /*  in - N, no. of trits in array */
    uint8_t *buf,            /*  in - temp buf, N octets */
    uint8_t *out);           /* out - address for packed octets */

/* ntru_elements_2_octets
 *
 * Packs an array of n-bit elements into an array of
 * ((in_len * n_bits) + 7) / 8 octets, 8 < n_bits < 16.
 */

extern void
ntru_elements_2_octets(
    uint16_t in_len,    /*  in - no. of elements to be packed */
    uint16_t const *in, /*  in - ptr to elements to be packed */
    uint8_t n_bits,     /*  in - no. of bits in input element */
    uint8_t *out);      /* out - addr for output octets */

/* ntru_octets_2_elements
 *
 * Unpacks an octet string into an array of ((in_len * 8) / n_bits)
 * n-bit elements, 8 < n < 16.  Any extra bits are discarded.
 */

extern void
ntru_octets_2_elements(
    uint16_t in_len,   /*  in - no. of octets to be unpacked */
    uint8_t const *in, /*  in - ptr to octets to be unpacked */
    uint8_t n_bits,    /*  in - no. of bits in output element */
    uint16_t *out);    /* out - addr for output elements */

#endif /* NTRU_CRYPTO_NTRU_CONVERT_H */
