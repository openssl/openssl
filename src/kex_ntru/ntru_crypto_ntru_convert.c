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
 * File: ntru_crypto_ntru_convert.c
 *
 * Contents: Conversion routines for NTRUEncrypt, including packing, unpacking,
 *           and others.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_convert.h"

/* 3-bit to 2-trit conversion tables: 2 represents -1 */

static uint8_t const bits_2_trit1[] = {0, 0, 0, 1, 1, 1, 2, 2};
static uint8_t const bits_2_trit2[] = {0, 1, 2, 0, 1, 2, 0, 1};

/* ntru_bits_2_trits
 *
 * Each 3 bits in an array of octets is converted to 2 trits in an array
 * of trits.
 *
 * The octet array may overlap the end of the trit array.
 */

void ntru_bits_2_trits(
    uint8_t const *octets, /*  in - pointer to array of octets */
    uint16_t num_trits,    /*  in - number of trits to produce */
    uint8_t *trits)        /* out - address for array of trits */
{
	uint32_t bits24;
	uint32_t bits3;
	uint32_t shift;

	while (num_trits >= 16) {
		/* get next three octets */

		bits24 = ((uint32_t)(*octets++)) << 16;
		bits24 |= ((uint32_t)(*octets++)) << 8;
		bits24 |= (uint32_t)(*octets++);

		/* for each 3 bits in the three octets, output 2 trits */

		bits3 = (bits24 >> 21) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 18) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 15) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 12) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 9) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 6) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = (bits24 >> 3) & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		bits3 = bits24 & 0x7;
		*trits++ = bits_2_trit1[bits3];
		*trits++ = bits_2_trit2[bits3];

		num_trits -= 16;
	}

	if (num_trits == 0) {
		return;
	}

	/* get three octets */

	bits24 = ((uint32_t)(*octets++)) << 16;
	bits24 |= ((uint32_t)(*octets++)) << 8;
	bits24 |= (uint32_t)(*octets++);

	shift = 21;
	while (num_trits) {
		/* for each 3 bits in the three octets, output up to 2 trits
         * until all trits needed are produced
         */

		bits3 = (bits24 >> shift) & 0x7;
		shift -= 3;
		*trits++ = bits_2_trit1[bits3];

		if (--num_trits) {
			*trits++ = bits_2_trit2[bits3];
			--num_trits;
		}
	}

	return;
}

/* ntru_trits_2_bits
 *
 * Each 2 trits in an array of trits is converted to 3 bits, and the bits
 * are packed in an array of octets.  A multiple of 3 octets is output.
 * Any bits in the final octets not derived from trits are zero.
 *
 * Returns TRUE if all trits were valid.
 * Returns FALSE if invalid trits were found.
 */

bool ntru_trits_2_bits(
    uint8_t const *trits, /*  in - pointer to array of trits */
    uint32_t num_trits,   /*  in - number of trits to convert */
    uint8_t *octets)      /* out - address for array of octets */
{
	bool all_trits_valid = TRUE;
	uint32_t bits24;
	uint32_t bits3;
	uint32_t shift;

	while (num_trits >= 16) {

		/* convert each 2 trits to 3 bits and pack */

		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 = (bits3 << 21);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 18);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 15);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 12);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 9);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 6);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << 3);
		bits3 = *trits++ * 3;
		bits3 += *trits++;

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= bits3;
		num_trits -= 16;

		/* output three octets */

		*octets++ = (uint8_t)((bits24 >> 16) & 0xff);
		*octets++ = (uint8_t)((bits24 >> 8) & 0xff);
		*octets++ = (uint8_t)(bits24 & 0xff);
	}

	bits24 = 0;
	shift = 21;

	while (num_trits) {

		/* convert each 2 trits to 3 bits and pack */

		bits3 = *trits++ * 3;

		if (--num_trits) {
			bits3 += *trits++;
			--num_trits;
		}

		if (bits3 > 7) {
			bits3 = 7;
			all_trits_valid = FALSE;
		}

		bits24 |= (bits3 << shift);
		shift -= 3;
	}

	/* output three octets */

	*octets++ = (uint8_t)((bits24 >> 16) & 0xff);
	*octets++ = (uint8_t)((bits24 >> 8) & 0xff);
	*octets++ = (uint8_t)(bits24 & 0xff);

	return all_trits_valid;
}

/* ntru_coeffs_mod4_2_octets
 *
 * Takes an array of ring element coefficients mod 4 and packs the
 * results into an octet string.
 */

void ntru_coeffs_mod4_2_octets(
    uint16_t num_coeffs,    /*  in - number of coefficients */
    uint16_t const *coeffs, /*  in - pointer to coefficients */
    uint8_t *octets)        /* out - address for octets */
{
	uint8_t bits2;
	int shift;
	uint16_t i;

	*octets = 0;
	shift = 6;
	for (i = 0; i < num_coeffs; i++) {
		bits2 = (uint8_t)(coeffs[i] & 0x3);
		*octets |= bits2 << shift;
		shift -= 2;

		if (shift < 0) {
			++octets;
			*octets = 0;
			shift = 6;
		}
	}

	return;
}

/* ntru_trits_2_octet
 *
 * Packs 5 trits in an octet, where a trit is 0, 1, or 2 (-1).
 */

void ntru_trits_2_octet(
    uint8_t const *trits, /*  in - pointer to trits */
    uint8_t *octet)       /* out - address for octet */
{
	int i;

	*octet = 0;
	for (i = 4; i >= 0; i--) {
		*octet = (*octet * 3) + trits[i];
	}

	return;
}

/* ntru_octet_2_trits
 *
 * Unpacks an octet to 5 trits, where a trit is 0, 1, or 2 (-1).
 */

void ntru_octet_2_trits(
    uint8_t octet,  /*  in - octet to be unpacked */
    uint8_t *trits) /* out - address for trits */
{
	int i;

	for (i = 0; i < 5; i++) {
		trits[i] = octet % 3;
		octet = (octet - trits[i]) / 3;
	}

	return;
}

/* ntru_indices_2_trits
 *
 * Converts a list of the nonzero indices of a polynomial into an array of
 * trits.
 */

void ntru_indices_2_trits(
    uint16_t in_len,    /*  in - no. of indices */
    uint16_t const *in, /*  in - pointer to list of indices */
    bool plus1,         /*  in - if list is +1 cofficients */
    uint8_t *out)       /* out - address of output polynomial */
{
	uint8_t trit = plus1 ? 1 : 2;
	uint16_t i;

	for (i = 0; i < in_len; i++) {
		out[in[i]] = trit;
	}

	return;
}

/* ntru_packed_trits_2_indices
 *
 * Unpacks an array of N trits and creates a list of array indices 
 * corresponding to trits = +1, and list of array indices corresponding to
 * trits = -1.
 */

void ntru_packed_trits_2_indices(
    uint8_t const *in,        /*  in - pointer to packed-trit octets */
    uint16_t num_trits,       /*  in - no. of packed trits */
    uint16_t *indices_plus1,  /* out - address for indices of +1 trits */
    uint16_t *indices_minus1) /* out - address for indices of -1 trits */
{
	uint8_t trits[5];
	uint16_t i = 0;
	int j;

	while (num_trits >= 5) {
		ntru_octet_2_trits(*in++, trits);
		num_trits -= 5;

		for (j = 0; j < 5; j++, i++) {
			if (trits[j] == 1) {
				*indices_plus1 = i;
				++indices_plus1;
			} else if (trits[j] == 2) {
				*indices_minus1 = i;
				++indices_minus1;
			} else {
				;
			}
		}
	}

	if (num_trits) {
		ntru_octet_2_trits(*in, trits);

		for (j = 0; num_trits && (j < 5); j++, i++) {
			if (trits[j] == 1) {
				*indices_plus1 = i;
				++indices_plus1;
			} else if (trits[j] == 2) {
				*indices_minus1 = i;
				++indices_minus1;
			} else {
				;
			}

			--num_trits;
		}
	}

	return;
}

/* ntru_indices_2_packed_trits
 *
 * Takes a list of array indices corresponding to elements whose values
 * are +1 or -1, and packs the N-element array of trits described by these
 * lists into octets, 5 trits per octet.
 */

void ntru_indices_2_packed_trits(
    uint16_t const *indices, /*  in - pointer to indices */
    uint16_t num_plus1,      /*  in - no. of indices for +1 trits */
    uint16_t num_minus1,     /*  in - no. of indices for -1 trits */
    uint16_t num_trits,      /*  in - N, no. of trits in array */
    uint8_t *buf,            /*  in - temp buf, N octets */
    uint8_t *out)            /* out - address for packed octets */
{

	/* convert indices to an array of trits */

	memset(buf, 0, num_trits);
	ntru_indices_2_trits(num_plus1, indices, TRUE, buf);
	ntru_indices_2_trits(num_minus1, indices + num_plus1, FALSE, buf);

	/* pack the array of trits */

	while (num_trits >= 5) {
		ntru_trits_2_octet(buf, out);
		num_trits -= 5;
		buf += 5;
		++out;
	}

	if (num_trits) {
		uint8_t trits[5];

		memcpy(trits, buf, num_trits);
		memset(trits + num_trits, 0, sizeof(trits) - num_trits);
		ntru_trits_2_octet(trits, out);
	}

	return;
}

/* ntru_elements_2_octets
 *
 * Packs an array of n-bit elements into an array of
 * ((in_len * n_bits) + 7) / 8 octets.
 * NOTE: Assumes 8 < n_bits < 16.
 */

void ntru_elements_2_octets(
    uint16_t in_len,    /*  in - no. of elements to be packed */
    uint16_t const *in, /*  in - ptr to elements to be packed */
    uint8_t n_bits,     /*  in - no. of bits in input element */
    uint8_t *out)       /* out - addr for output octets */
{
	uint16_t temp;
	uint16_t shift;
	uint16_t i;

	/* pack */

	temp = 0;
	shift = n_bits - 8;
	i = 0;
	while (i < in_len) {
		/* add bits to temp to fill an octet and output the octet */
		temp |= in[i] >> shift;
		*out++ = (uint8_t)(temp & 0xff);
		if (shift > 8) {
			/* next full octet is in current input word */

			shift = shift - 8;
			temp = 0;
		} else {
			shift = 8 - shift;
			/* put remaining bits of input word in temp as partial octet,
             * and increment index to next input word
             */
			temp = in[i] << shift;
			shift = n_bits - shift;

			++i;
		}
	}

	/* output any bits remaining in last input word */

	if (shift != n_bits - 8) {
		*out++ = (uint8_t)(temp & 0xff);
	}

	return;
}

/* ntru_octets_2_elements
 *
 * Unpacks an octet string into an array of ((in_len * 8) / n_bits)
 * n-bit elements.  Any extra bits are discarded.
 * NOTE: Assumes 8 < n_bits < 16.
 */

void ntru_octets_2_elements(
    uint16_t in_len,   /*  in - no. of octets to be unpacked */
    uint8_t const *in, /*  in - ptr to octets to be unpacked */
    uint8_t n_bits,    /*  in - no. of bits in output element */
    uint16_t *out)     /* out - addr for output elements */
{
	uint16_t temp;
	uint16_t mask;
	uint16_t shift;
	uint16_t i;

	/* unpack */

	temp = 0;
	mask = (1 << n_bits) - 1;
	shift = n_bits;
	i = 0;

	while (i < in_len) {
		if (shift > 8) {
			/* the current octet will not fill the current element */

			shift = shift - 8;
			temp |= ((uint16_t) in[i]) << shift;
		} else {
			/* add bits from the current octet to fill the current element and
             * output the element
             */

			shift = 8 - shift;

			temp |= ((uint16_t) in[i]) >> shift;
			*out++ = temp & mask;

			/* add the remaining bits of the current octet to start an element */
			shift = n_bits - shift;
			temp = ((uint16_t) in[i]) << shift;
		}
		++i;
	}

	return;
}
