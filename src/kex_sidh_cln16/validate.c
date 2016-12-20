/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: functions for validation of public keys
*
* SECURITY NOTE: these functions run in variable time because it is assumed that they are
*                used over public data.
*
*********************************************************************************************/

#include <oqs/rand.h>
#include "SIDH_internal.h"

static bool is_equal_fp(oqs_sidh_cln16_felm_t a, oqs_sidh_cln16_felm_t b) {
	// Return true if a = b in GF(p751). Otherwise, return false
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++) {
		if (a[i] != b[i]) {
			return false;
		}
	}

	return true;
}


static bool is_equal_fp2(oqs_sidh_cln16_f2elm_t a, oqs_sidh_cln16_f2elm_t b) {
	// Return true if a = b in GF(p751^2). Otherwise, return false

	return (is_equal_fp(a[0], b[0]) && is_equal_fp(a[1], b[1]));
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_random_fp2(oqs_sidh_cln16_f2elm_t f2value, PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand) {
	// Output random value in GF(p751). It makes requests of random values to the "random_bytes" function.
	// If successful, the output is given in "f2value".
	unsigned int ntry = 0, nbytes;
	oqs_sidh_cln16_felm_t t1, p751;
	unsigned char mask;
	oqs_sidh_cln16_clear_words((void *)f2value, 2 * NWORDS_FIELD);
	oqs_sidh_cln16_fpcopy751(pCurveIsogeny->prime, p751);
	nbytes = (pCurveIsogeny->pbits + 7) / 8;                   // Number of random bytes to be requested
	mask = (unsigned char)(8 * nbytes - pCurveIsogeny->pbits);
	mask = ((unsigned char) - 1 >> mask);                      // Value for masking last random byte

	do {
		ntry++;
		if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, p751-1]
			return SIDH_CRYPTO_ERROR_TOO_MANY_ITERATIONS;
		}

		rand->rand_n(rand, (uint8_t *)&f2value[0], nbytes);
		((unsigned char *)&f2value[0])[nbytes - 1] &= mask;    // Masking last byte
	} while (oqs_sidh_cln16_mp_sub(p751, f2value[0], t1, NWORDS_FIELD) == 1);

	ntry = 0;
	do {
		ntry++;
		if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, p751-1]
			return SIDH_CRYPTO_ERROR_TOO_MANY_ITERATIONS;
		}

		rand->rand_n(rand, (uint8_t *)&f2value[1], nbytes);
		((unsigned char *)&f2value[1])[nbytes - 1] &= mask;    // Masking last byte
	} while (oqs_sidh_cln16_mp_sub(p751, f2value[1], t1, NWORDS_FIELD) == 1);

// Cleanup
	oqs_sidh_cln16_clear_words((void *)t1, NWORDS_FIELD);

	return SIDH_CRYPTO_SUCCESS;
}


static bool test_curve(oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_f2elm_t rvalue, PCurveIsogenyStruct CurveIsogeny) {
	// This function checks that the curve is in the correct supersingular isogeny class via Sutherland's Monte Carlo algorithm.
	// It also checks that the curve is not a subfield curve. Both Alice and Bob call this same function in their respective validation procedures below.
	// Inputs: the curve constant A, corresponding to E_A: y^2=x^3+A*x^2+x,
	//         a random value "rvalue" in Fp2.
	// Output: returns "true" if curve is valid, "false" otherwise.
	oqs_sidh_cln16_f2elm_t t0, t1, one = { {0} }, zero = { {0} };
	oqs_sidh_cln16_point_proj_t rP, P1;
	bool valid_curve;

	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, one[0]);

	// Test j invariant in Fp2\Fp
	oqs_sidh_cln16_fp2sqr751_mont(A, t0);                             // t0 = a^2
	oqs_sidh_cln16_fp2sub751(t0, one, t0);
	oqs_sidh_cln16_fp2sub751(t0, one, t0);
	oqs_sidh_cln16_fp2sub751(t0, one, t0);                            // t0 = t0-3
	oqs_sidh_cln16_fp2sqr751_mont(t0, t1);                            // t1 = t0^2
	oqs_sidh_cln16_fp2mul751_mont(t0, t1, t1);                        // t1 = t1*t0
	oqs_sidh_cln16_fp2sub751(t0, one, t0);                            // t0 = t0-1
	oqs_sidh_cln16_fpmul751_mont(t1[0], t0[1], t1[0]);
	oqs_sidh_cln16_fpmul751_mont(t1[1], t0[0], t1[1]);
	oqs_sidh_cln16_fp2correction751(t1);

	valid_curve = !is_equal_fp(t1[0], t1[1]);

	// Test supersingular
	oqs_sidh_cln16_fp2copy751(rvalue, rP->X);
	oqs_sidh_cln16_fp2copy751(one, rP->Z);

	oqs_sidh_cln16_xDBLe(rP, rP, A, one, 1);
	oqs_sidh_cln16_xDBLe(rP, P1, A, one, 371);
	oqs_sidh_cln16_xTPLe(P1, P1, A, one, 239);
	oqs_sidh_cln16_fp2mul751_mont(rP->X, P1->Z, rP->X);               // X = X*Z1
	oqs_sidh_cln16_fp2mul751_mont(rP->Z, P1->X, rP->Z);               // Z = Z*X1
	oqs_sidh_cln16_fp2sub751(rP->X, rP->Z, rP->X);                    // X = X-Z
	oqs_sidh_cln16_fp2mul751_mont(rP->X, P1->Z, rP->X);               // X = X*Z1
	oqs_sidh_cln16_fp2correction751(rP->X);

	return (valid_curve && is_equal_fp2(rP->X, zero));
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_Validate_PKA(oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_publickey_t PKA, bool *valid, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Bob validating Alice's public key
	// Inputs: Alice's public key [A,xP,xQ,xQP], where xP,xQ and xQP are contained in PKA,
	//         the exponent eB (=239 for our curve) for Miller's algorithm.
	// Output: valid = "true" if key is valid, "false" otherwise.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int eB1 = CurveIsogeny->eB - 1;    // eB1 = eB-1
	oqs_sidh_cln16_f2elm_t t0, t1, rvalue, one = { {0} }, zero = { {0} };
	oqs_sidh_cln16_point_proj_t P = oqs_sidh_cln16_point_proj_t_EMPTY, Q = oqs_sidh_cln16_point_proj_t_EMPTY;
	SIDH_CRYPTO_STATUS Status;

	// Choose a random element in GF(p751^2) for Sutherland's algorithm. Assume that it is in Montgomery representation
	Status = oqs_sidh_cln16_random_fp2(rvalue, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)rvalue, 2 * NWORDS_FIELD);
		return Status;
	}

	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, one[0]);
	oqs_sidh_cln16_fp2copy751(PKA[0], P->X);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, P->Z[0]);
	oqs_sidh_cln16_fp2copy751(PKA[1], Q->X);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, Q->Z[0]);

	oqs_sidh_cln16_xTPLe(P, P, A, one, eB1);
	oqs_sidh_cln16_xTPLe(Q, Q, A, one, eB1);
	oqs_sidh_cln16_fp2mul751_mont(P->X, Q->Z, t0);                         // t0 = XP*ZQ
	oqs_sidh_cln16_fp2mul751_mont(Q->X, P->Z, t1);                         // t1 = XQ*ZP
	oqs_sidh_cln16_fp2sub751(t0, t1, t0);                                  // t0 = t0-t1
	oqs_sidh_cln16_fp2mul751_mont(P->Z, t0, t0);                           // t0 = ZP*t0
	oqs_sidh_cln16_fp2mul751_mont(Q->Z, t0, t0);                           // t0 = ZQ*t0
	oqs_sidh_cln16_fp2correction751(t0);
	*valid = !is_equal_fp2(t0, zero);                       // Checks that ZP*ZQ*(XQ*ZP-XP*ZQ) != 0, i.e., that 3^(e-1)*P != 3^(e-1)*Q and neither P nor Q has order 3^(e-1)

	oqs_sidh_cln16_xTPLe(P, P, A, one, 1);
	oqs_sidh_cln16_xTPLe(Q, Q, A, one, 1);
	oqs_sidh_cln16_fp2correction751(P->Z);
	oqs_sidh_cln16_fp2correction751(Q->Z);
	*valid = *valid & is_equal_fp2(P->Z, zero);             // Checks that 3^e*P = 0
	*valid = *valid & is_equal_fp2(Q->Z, zero);             // Checks that 3^e*Q = 0
	*valid = *valid & test_curve(A, rvalue, CurveIsogeny);  // Tests curve via Sutherland's algorithm

	return SIDH_CRYPTO_SUCCESS;
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_Validate_PKB(oqs_sidh_cln16_f2elm_t A, oqs_sidh_cln16_publickey_t PKB, bool *valid, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Alice validating Bob's public key
	// Inputs: Bob's public key [A,xP,xQ,xQP], where xP,xQ and xQP are contained in PKB,
	//         the exponent eA (=372 for our curve) for Miller's algorithm.
	// Output: valid = "true" if key is valid, "false" otherwise.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int oAbits2 = CurveIsogeny->oAbits - 2;    // oAbits2 = oAbits-2
	oqs_sidh_cln16_f2elm_t t0, t1, two, four, rvalue, one = { {0} }, zero = { {0} };
	oqs_sidh_cln16_point_proj_t P = oqs_sidh_cln16_point_proj_t_EMPTY, Q = oqs_sidh_cln16_point_proj_t_EMPTY;
	SIDH_CRYPTO_STATUS Status;

	// Choose a random element in GF(p751^2) for Sutherland's algorithm. Assume that it is in Montgomery representation
	Status = oqs_sidh_cln16_random_fp2(rvalue, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)rvalue, 2 * NWORDS_FIELD);
		return Status;
	}

	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, one[0]);
	oqs_sidh_cln16_fp2copy751(PKB[0], P->X);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, P->Z[0]);
	oqs_sidh_cln16_fp2copy751(PKB[1], Q->X);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, Q->Z[0]);

	oqs_sidh_cln16_fp2add751(one, one, two);
	oqs_sidh_cln16_fp2add751(two, two, four);                              // four = 4
	oqs_sidh_cln16_xDBLe(P, P, A, one, oAbits2);
	oqs_sidh_cln16_xDBLe(Q, Q, A, one, oAbits2);
	oqs_sidh_cln16_fp2mul751_mont(P->X, Q->Z, t0);                         // t0 = XP*ZQ
	oqs_sidh_cln16_fp2mul751_mont(Q->X, P->Z, t1);                         // t1 = XQ*ZP
	oqs_sidh_cln16_fp2sub751(t0, t1, t0);                                  // t0 = t0-t1
	oqs_sidh_cln16_fp2mul751_mont(P->Z, t0, t0);                           // t0 = ZP*t0
	oqs_sidh_cln16_fp2mul751_mont(Q->Z, t0, t0);                           // t0 = ZQ*t0
	oqs_sidh_cln16_fp2correction751(t0);
	*valid = !is_equal_fp2(t0, zero);                       // Checks that ZP*ZQ*(XQ*ZP-XP*ZQ) != 0, i.e., that 2^(e-2)*P != 2^(e-2)*Q and neither P nor Q has order 2^(e-2)

	oqs_sidh_cln16_fp2add751(A, two, t0);                                  // t0 = A+2
	oqs_sidh_cln16_xDBL(P, P, t0, four);
	oqs_sidh_cln16_xDBL(Q, Q, t0, four);
	oqs_sidh_cln16_fp2mul751_mont(P->Z, Q->Z, t0);                         // t0 = ZP*ZQ
	oqs_sidh_cln16_fp2correction751(t0);
	*valid = *valid & !is_equal_fp2(t0, zero);              // Checks that 2^(e-1)*P != 0 and 2^(e-1)*Q != 0

	oqs_sidh_cln16_xDBL(P, P, t0, four);
	oqs_sidh_cln16_xDBL(Q, Q, t0, four);
	oqs_sidh_cln16_fp2correction751(P->Z);
	oqs_sidh_cln16_fp2correction751(Q->Z);
	*valid = *valid & is_equal_fp2(P->Z, zero);             // Checks that 2^e*P = 0
	*valid = *valid & is_equal_fp2(Q->Z, zero);             // Checks that 2^e*Q = 0
	*valid = *valid & test_curve(A, rvalue, CurveIsogeny);  // Tests curve via Sutherland's algorithm

	return SIDH_CRYPTO_SUCCESS;
}
