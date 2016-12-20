/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: functions for initialization and getting randomness
*
*********************************************************************************************/

#include <stdlib.h>
#include <oqs/rand.h>
#include "SIDH_internal.h"


SIDH_CRYPTO_STATUS oqs_sidh_cln16_curve_initialize(PCurveIsogenyStruct pCurveIsogeny, UNUSED OQS_RAND *rand, PCurveIsogenyStaticData pCurveIsogenyData) {
	// Initialize curve isogeny structure pCurveIsogeny with static data extracted from pCurveIsogenyData.
	// This needs to be called after allocating memory for "pCurveIsogeny" using oqs_sidh_cln16_curve_allocate().
	unsigned int i, pwords, owords;

	if (oqs_sidh_cln16_is_CurveIsogenyStruct_null(pCurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	for (i = 0; i < 8; i++) {    // Copy 8-character identifier
		pCurveIsogeny->CurveIsogeny[i] = pCurveIsogenyData->CurveIsogeny[i];
	}
	pCurveIsogeny->pwordbits = pCurveIsogenyData->pwordbits;
	pCurveIsogeny->owordbits = pCurveIsogenyData->owordbits;
	pCurveIsogeny->pbits = pCurveIsogenyData->pbits;
	pCurveIsogeny->oAbits = pCurveIsogenyData->oAbits;
	pCurveIsogeny->oBbits = pCurveIsogenyData->oBbits;
	pCurveIsogeny->eB = pCurveIsogenyData->eB;
	pCurveIsogeny->BigMont_A24 = pCurveIsogenyData->BigMont_A24;

	pwords = (pCurveIsogeny->pwordbits + RADIX - 1) / RADIX;
	owords = (pCurveIsogeny->owordbits + RADIX - 1) / RADIX;
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->prime, pCurveIsogeny->prime, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->A, pCurveIsogeny->A, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->C, pCurveIsogeny->C, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->Aorder, pCurveIsogeny->Aorder, owords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->Border, pCurveIsogeny->Border, owords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->PA, pCurveIsogeny->PA, 2 * pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->PB, pCurveIsogeny->PB, 2 * pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->BigMont_order, pCurveIsogeny->BigMont_order, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->Montgomery_R2, pCurveIsogeny->Montgomery_R2, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->Montgomery_pp, pCurveIsogeny->Montgomery_pp, pwords);
	oqs_sidh_cln16_copy_words((digit_t *)pCurveIsogenyData->Montgomery_one, pCurveIsogeny->Montgomery_one, pwords);

	return SIDH_CRYPTO_SUCCESS;
}


PCurveIsogenyStruct oqs_sidh_cln16_curve_allocate(PCurveIsogenyStaticData CurveData) {
	// Dynamic allocation of memory for curve isogeny structure.
	// Returns NULL on error.
	digit_t pbytes = (CurveData->pwordbits + 7) / 8;
	digit_t obytes = (CurveData->owordbits + 7) / 8;
	PCurveIsogenyStruct pCurveIsogeny = (PCurveIsogenyStruct)calloc(1, sizeof(CurveIsogenyStruct));
	if (!pCurveIsogeny) {
		return NULL;
	}
	pCurveIsogeny->prime = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->A = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->C = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->Aorder = (digit_t *)calloc(1, obytes);
	pCurveIsogeny->Border = (digit_t *)calloc(1, obytes);
	pCurveIsogeny->PA = (digit_t *)calloc(1, 2 * pbytes);
	pCurveIsogeny->PB = (digit_t *)calloc(1, 2 * pbytes);
	pCurveIsogeny->BigMont_order = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->Montgomery_R2 = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->Montgomery_pp = (digit_t *)calloc(1, pbytes);
	pCurveIsogeny->Montgomery_one = (digit_t *)calloc(1, pbytes);
	if (oqs_sidh_cln16_is_CurveIsogenyStruct_null(pCurveIsogeny)) {
		oqs_sidh_cln16_curve_free(pCurveIsogeny);
		return NULL;
	}
	return pCurveIsogeny;
}


void oqs_sidh_cln16_curve_free(PCurveIsogenyStruct pCurveIsogeny) {
	// Free memory for curve isogeny structure

	if (pCurveIsogeny != NULL) {
		if (pCurveIsogeny->prime != NULL) {
			free(pCurveIsogeny->prime);
		}
		if (pCurveIsogeny->A != NULL) {
			free(pCurveIsogeny->A);
		}
		if (pCurveIsogeny->C != NULL) {
			free(pCurveIsogeny->C);
		}
		if (pCurveIsogeny->Aorder != NULL) {
			free(pCurveIsogeny->Aorder);
		}
		if (pCurveIsogeny->Border != NULL) {
			free(pCurveIsogeny->Border);
		}
		if (pCurveIsogeny->PA != NULL) {
			free(pCurveIsogeny->PA);
		}
		if (pCurveIsogeny->PB != NULL) {
			free(pCurveIsogeny->PB);
		}
		if (pCurveIsogeny->BigMont_order != NULL) {
			free(pCurveIsogeny->BigMont_order);
		}
		if (pCurveIsogeny->Montgomery_R2 != NULL) {
			free(pCurveIsogeny->Montgomery_R2);
		}
		if (pCurveIsogeny->Montgomery_pp != NULL) {
			free(pCurveIsogeny->Montgomery_pp);
		}
		if (pCurveIsogeny->Montgomery_one != NULL) {
			free(pCurveIsogeny->Montgomery_one);
		}

		free(pCurveIsogeny);
	}
}


bool oqs_sidh_cln16_is_CurveIsogenyStruct_null(PCurveIsogenyStruct pCurveIsogeny) {
	// Check if curve isogeny structure is NULL

	if (pCurveIsogeny == NULL || pCurveIsogeny->prime == NULL || pCurveIsogeny->A == NULL || pCurveIsogeny->C == NULL || pCurveIsogeny->Aorder == NULL || pCurveIsogeny->Border == NULL ||
	        pCurveIsogeny->PA == NULL || pCurveIsogeny->PB == NULL || pCurveIsogeny->BigMont_order == NULL || pCurveIsogeny->Montgomery_R2 == NULL || pCurveIsogeny->Montgomery_pp == NULL ||
	        pCurveIsogeny->Montgomery_one == NULL) {
		return true;
	}
	return false;
}

const uint64_t Border_div3[SIDH_NWORDS_ORDER] = { 0xEDCD718A828384F9, 0x733B35BFD4427A14, 0xF88229CF94D7CF38, 0x63C56C990C7C2AD6, 0xB858A87E8F4222C7, 0x254C9C6B525EAF5 };


SIDH_CRYPTO_STATUS oqs_sidh_cln16_random_mod_order(digit_t *random_digits, unsigned int AliceOrBob, PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand) {
	// Output random values in the range [1, order-1] in little endian format that can be used as private keys.
	// It makes requests of random values with length "oAbits" (when AliceOrBob = 0) or "oBbits" (when AliceOrBob = 1).
	// The process repeats until random value is in [0, Aorder-2]  ([0, Border-2], resp.).
	// If successful, the output is given in "random_digits" in the range [1, Aorder-1] ([1, Border-1], resp.).
	unsigned int ntry = 0, nbytes, nwords;
	digit_t t1[SIDH_MAXWORDS_ORDER] = {0}, order2[SIDH_MAXWORDS_ORDER] = {0};
	unsigned char mask;
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (random_digits == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(pCurveIsogeny) || AliceOrBob > 1) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_clear_words((void *)random_digits, SIDH_MAXWORDS_ORDER);
	t1[0] = 2;
	if (AliceOrBob == SIDH_ALICE) {
		nbytes = (pCurveIsogeny->oAbits + 7) / 8;              // Number of random bytes to be requested
		nwords = NBITS_TO_NWORDS(pCurveIsogeny->oAbits);
		mask = 0x07;                                           // Value for masking last random byte
		oqs_sidh_cln16_copy_words(pCurveIsogeny->Aorder, order2, nwords);
		oqs_sidh_cln16_mp_shiftr1(order2, nwords);                            // order/2
		oqs_sidh_cln16_mp_sub(order2, t1, order2, nwords);                    // order2 = order/2-2
	} else {
		nbytes = (pCurveIsogeny->oBbits + 7) / 8;
		nwords = NBITS_TO_NWORDS(pCurveIsogeny->oBbits);
		mask = 0x03;                                           // Value for masking last random byte
		oqs_sidh_cln16_mp_sub((digit_t *)Border_div3, t1, order2, nwords);    // order2 = order/3-2
	}

	do {
		ntry++;
		if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, order-2]
			return SIDH_CRYPTO_ERROR_TOO_MANY_ITERATIONS;
		}

		rand->rand_n(rand, (uint8_t *) random_digits, nbytes);
		((unsigned char *)random_digits)[nbytes - 1] &= mask;  // Masking last byte
	} while (oqs_sidh_cln16_mp_sub(order2, random_digits, t1, nwords) == 1);

	oqs_sidh_cln16_clear_words((void *)t1, SIDH_MAXWORDS_ORDER);
	t1[0] = 1;
	oqs_sidh_cln16_mp_add(random_digits, t1, random_digits, nwords);
	oqs_sidh_cln16_copy_words(random_digits, t1, nwords);
	oqs_sidh_cln16_mp_shiftl1(random_digits, nwords);                         // Alice's output in the range [2, order-2]
	if (AliceOrBob == SIDH_BOB) {
		oqs_sidh_cln16_mp_add(random_digits, t1, random_digits, nwords);      // Bob's output in the range [3, order-3]
	}

	return Status;
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_random_BigMont_mod_order(digit_t *random_digits, PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand) {
	// Output random values in the range [1, BigMont_order-1] in little endian format that can be used as private keys to compute scalar multiplications
	// using the elliptic curve BigMont.
	// It makes requests of random values with length "BIGMONT_NBITS_ORDER".
	// The process repeats until random value is in [0, BigMont_order-2]
	// If successful, the output is given in "random_digits" in the range [1, BigMont_order-1].
	unsigned int ntry = 0, nbytes = (BIGMONT_NBITS_ORDER + 7) / 8, nwords = NBITS_TO_NWORDS(BIGMONT_NBITS_ORDER);
	digit_t t1[BIGMONT_MAXWORDS_ORDER] = {0}, order2[BIGMONT_MAXWORDS_ORDER] = {0};
	unsigned char mask;
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (random_digits == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(pCurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_clear_words((void *)random_digits, BIGMONT_MAXWORDS_ORDER);
	t1[0] = 2;
	mask = (unsigned char)(8 * nbytes - BIGMONT_NBITS_ORDER);
	oqs_sidh_cln16_mp_sub(pCurveIsogeny->BigMont_order, t1, order2, nwords);  // order2 = order-2
	mask = ((unsigned char) - 1 >> mask);                      // Value for masking last random byte

	do {
		ntry++;
		if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, order-2]
			return SIDH_CRYPTO_ERROR_TOO_MANY_ITERATIONS;
		}
		rand->rand_n(rand, (uint8_t *)random_digits, nbytes);
		((unsigned char *)random_digits)[nbytes - 1] &= mask;  // Masking last byte
	} while (oqs_sidh_cln16_mp_sub(order2, random_digits, t1, nwords) == 1);

	oqs_sidh_cln16_clear_words((void *)t1, BIGMONT_MAXWORDS_ORDER);
	t1[0] = 1;
	oqs_sidh_cln16_mp_add(random_digits, t1, random_digits, nwords);          // Output in the range [1, order-1]

	return Status;
}


void oqs_sidh_cln16_clear_words(void *mem, digit_t nwords) {
	// Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
	// This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
	unsigned int i;
	volatile digit_t *v = mem;

	for (i = 0; i < nwords; i++) {
		v[i] = 0;
	}
}






