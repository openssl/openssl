/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral  
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: ephemeral isogeny-based key exchange
*
*********************************************************************************************/

#include "SIDH_internal.h"

extern const unsigned int splits_Alice[SIDH_MAX_Alice];
extern const unsigned int splits_Bob[SIDH_MAX_Bob];

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralKeyGeneration_A(unsigned char *PrivateKeyA, unsigned char *PublicKeyA, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) { // Alice's ephemeral key-pair generation
	                                                                                                                                                                  // It produces a private key PrivateKeyA and computes the public key PublicKeyA.
	                                                                                                                                                                  // The private key is an even integer in the range [2, oA-2], where oA = 2^372.
	                                                                                                                                                                  // The public key consists of 3 elements in GF(p751^2).
	                                                                                                                                                                  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	oqs_sidh_cln16_point_basefield_t P;
	oqs_sidh_cln16_point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[SIDH_MAX_INT_POINTS_ALICE];
	oqs_sidh_cln16_publickey_t *PublicKey = (oqs_sidh_cln16_publickey_t *) PublicKeyA;
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_ALICE], npts = 0;
	oqs_sidh_cln16_f2elm_t coeff[5], A = {0}, C = {0}, Aout, Cout;
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (PrivateKeyA == NULL || PublicKey == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	// Choose a random even number in the range [2, oA-2] as secret key for Alice
	Status = oqs_sidh_cln16_random_mod_order((digit_t *) PrivateKeyA, SIDH_ALICE, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *) PrivateKeyA, owords);
		return Status;
	}

	oqs_sidh_cln16_to_mont((digit_t *) CurveIsogeny->PA, (digit_t *) P); // Conversion of Alice's generators to Montgomery representation
	oqs_sidh_cln16_to_mont(((digit_t *) CurveIsogeny->PA) + NWORDS_FIELD, ((digit_t *) P) + NWORDS_FIELD);

	Status = oqs_sidh_cln16_secret_pt(P, (digit_t *) PrivateKeyA, SIDH_ALICE, R, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *) PrivateKeyA, owords);
		return Status;
	}

	oqs_sidh_cln16_copy_words((digit_t *) CurveIsogeny->PB, (digit_t *) phiP, pwords); // Copy X-coordinates from Bob's public parameters, set Z <- 1
	oqs_sidh_cln16_fpcopy751((digit_t *) CurveIsogeny->Montgomery_one, (digit_t *) phiP->Z);
	oqs_sidh_cln16_to_mont((digit_t *) phiP, (digit_t *) phiP);
	oqs_sidh_cln16_copy_words((digit_t *) phiP, (digit_t *) phiQ, pwords); // QB = (-XPB:1)
	oqs_sidh_cln16_fpneg751(phiQ->X[0]);
	oqs_sidh_cln16_fpcopy751((digit_t *) CurveIsogeny->Montgomery_one, (digit_t *) phiQ->Z);
	oqs_sidh_cln16_distort_and_diff(phiP->X[0], phiD, CurveIsogeny); // DB = (x(QB-PB),z(QB-PB))

	oqs_sidh_cln16_fpcopy751(CurveIsogeny->A, A[0]); // Extracting curve parameters A and C
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(A[0], A[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	oqs_sidh_cln16_first_4_isog(phiP, A, Aout, Cout, CurveIsogeny);
	oqs_sidh_cln16_first_4_isog(phiQ, A, Aout, Cout, CurveIsogeny);
	oqs_sidh_cln16_first_4_isog(phiD, A, Aout, Cout, CurveIsogeny);
	oqs_sidh_cln16_first_4_isog(R, A, A, C, CurveIsogeny);

	index = 0;
	for (row = 1; row < SIDH_MAX_Alice; row++) {
		while (index < SIDH_MAX_Alice - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Alice[SIDH_MAX_Alice - index - row];
			oqs_sidh_cln16_xDBLe(R, R, A, C, (int) (2 * m));
			index += m;
		}
		oqs_sidh_cln16_get_4_isog(R, A, C, coeff);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_4_isog(pts[i], coeff);
		}
		oqs_sidh_cln16_eval_4_isog(phiP, coeff);
		oqs_sidh_cln16_eval_4_isog(phiQ, coeff);
		oqs_sidh_cln16_eval_4_isog(phiD, coeff);

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_4_isog(R, A, C, coeff);
	oqs_sidh_cln16_eval_4_isog(phiP, coeff);
	oqs_sidh_cln16_eval_4_isog(phiQ, coeff);
	oqs_sidh_cln16_eval_4_isog(phiD, coeff);

	oqs_sidh_cln16_inv_3_way(phiP->Z, phiQ->Z, phiD->Z);
	oqs_sidh_cln16_fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
	oqs_sidh_cln16_fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
	oqs_sidh_cln16_fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

	oqs_sidh_cln16_from_fp2mont(phiP->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[0]); // Converting back to standard representation
	oqs_sidh_cln16_from_fp2mont(phiQ->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[1]);
	oqs_sidh_cln16_from_fp2mont(phiD->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[2]);

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiP, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiQ, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiD, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_ALICE * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) coeff, 5 * 2 * pwords);

	return Status;
}

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralKeyGeneration_B(unsigned char *PrivateKeyB, unsigned char *PublicKeyB, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) { // Bob's ephemeral key-pair generation
	                                                                                                                                                                  // It produces a private key PrivateKeyB and computes the public key PublicKeyB.
	                                                                                                                                                                  // The private key is an integer in the range [1, oB-1], where oA = 3^239.
	                                                                                                                                                                  // The public key consists of 3 elements in GF(p751^2).
	                                                                                                                                                                  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	oqs_sidh_cln16_point_basefield_t P;
	oqs_sidh_cln16_point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[SIDH_MAX_INT_POINTS_BOB];
	oqs_sidh_cln16_publickey_t *PublicKey = (oqs_sidh_cln16_publickey_t *) PublicKeyB;
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_BOB], npts = 0;
	oqs_sidh_cln16_f2elm_t A = {0}, C = {0};
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (PrivateKeyB == NULL || PublicKey == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	// Choose a random number equivalent to 0 (mod 3) in the range [3, oB-3] as secret key for Bob
	Status = oqs_sidh_cln16_random_mod_order((digit_t *) PrivateKeyB, SIDH_BOB, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *) PrivateKeyB, owords);
		return Status;
	}

	oqs_sidh_cln16_to_mont((digit_t *) CurveIsogeny->PB, (digit_t *) P); // Conversion of Bob's generators to Montgomery representation
	oqs_sidh_cln16_to_mont(((digit_t *) CurveIsogeny->PB) + NWORDS_FIELD, ((digit_t *) P) + NWORDS_FIELD);

	Status = oqs_sidh_cln16_secret_pt(P, (digit_t *) PrivateKeyB, SIDH_BOB, R, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *) PrivateKeyB, owords);
		return Status;
	}

	oqs_sidh_cln16_copy_words((digit_t *) CurveIsogeny->PA, (digit_t *) phiP, pwords); // Copy X-coordinates from Alice's public parameters, set Z <- 1
	oqs_sidh_cln16_fpcopy751((digit_t *) CurveIsogeny->Montgomery_one, (digit_t *) phiP->Z);
	oqs_sidh_cln16_to_mont((digit_t *) phiP, (digit_t *) phiP);            // Conversion to Montgomery representation
	oqs_sidh_cln16_copy_words((digit_t *) phiP, (digit_t *) phiQ, pwords); // QA = (-XPA:1)
	oqs_sidh_cln16_fpneg751(phiQ->X[0]);
	oqs_sidh_cln16_fpcopy751((digit_t *) CurveIsogeny->Montgomery_one, (digit_t *) phiQ->Z);
	oqs_sidh_cln16_distort_and_diff(phiP->X[0], phiD, CurveIsogeny); // DA = (x(QA-PA),z(QA-PA))

	oqs_sidh_cln16_fpcopy751(CurveIsogeny->A, A[0]); // Extracting curve parameters A and C
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(A[0], A[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	index = 0;
	for (row = 1; row < SIDH_MAX_Bob; row++) {
		while (index < SIDH_MAX_Bob - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Bob[SIDH_MAX_Bob - index - row];
			oqs_sidh_cln16_xTPLe(R, R, A, C, (int) m);
			index += m;
		}
		oqs_sidh_cln16_get_3_isog(R, A, C);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_3_isog(R, pts[i]);
		}
		oqs_sidh_cln16_eval_3_isog(R, phiP);
		oqs_sidh_cln16_eval_3_isog(R, phiQ);
		oqs_sidh_cln16_eval_3_isog(R, phiD);

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_3_isog(R, A, C);
	oqs_sidh_cln16_eval_3_isog(R, phiP);
	oqs_sidh_cln16_eval_3_isog(R, phiQ);
	oqs_sidh_cln16_eval_3_isog(R, phiD);

	oqs_sidh_cln16_inv_3_way(phiP->Z, phiQ->Z, phiD->Z);
	oqs_sidh_cln16_fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
	oqs_sidh_cln16_fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
	oqs_sidh_cln16_fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

	oqs_sidh_cln16_from_fp2mont(phiP->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[0]); // Converting back to standard representation
	oqs_sidh_cln16_from_fp2mont(phiQ->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[1]);
	oqs_sidh_cln16_from_fp2mont(phiD->X, ((oqs_sidh_cln16_f2elm_t *) PublicKey)[2]);

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiP, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiQ, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) phiD, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_BOB * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);

	return Status;
}

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralSecretAgreement_A(const unsigned char *PrivateKeyA, const unsigned char *PublicKeyB, unsigned char *SharedSecretA, PCurveIsogenyStruct CurveIsogeny) { // Alice's ephemeral shared secret computation
	                                                                                                                                                                                              // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
	                                                                                                                                                                                              // Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372.
	                                                                                                                                                                                              //         Bob's PublicKeyB consists of 3 elements in GF(p751^2).
	                                                                                                                                                                                              // Output: a shared secret SharedSecretA that consists of one element in GF(p751^2).
	                                                                                                                                                                                              // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_ALICE], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_ALICE];
	oqs_sidh_cln16_publickey_t *PublicKey = (oqs_sidh_cln16_publickey_t *) PublicKeyB;
	oqs_sidh_cln16_f2elm_t jinv, coeff[5], PKB[3], A, C = {0};
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (PrivateKeyA == NULL || PublicKey == NULL || SharedSecretA == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[0], PKB[0]); // Extracting and converting Bob's public curve parameters to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[1], PKB[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[2], PKB[2]);

	oqs_sidh_cln16_get_A(PKB[0], PKB[1], PKB[2], A, CurveIsogeny);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	Status = oqs_sidh_cln16_ladder_3_pt(PKB[0], PKB[1], PKB[2], (digit_t *) PrivateKeyA, SIDH_ALICE, R, A, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		return Status;
	}
	oqs_sidh_cln16_first_4_isog(R, A, A, C, CurveIsogeny);

	index = 0;
	for (row = 1; row < SIDH_MAX_Alice; row++) {
		while (index < SIDH_MAX_Alice - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Alice[SIDH_MAX_Alice - index - row];
			oqs_sidh_cln16_xDBLe(R, R, A, C, (int) (2 * m));
			index += m;
		}
		oqs_sidh_cln16_get_4_isog(R, A, C, coeff);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_4_isog(pts[i], coeff);
		}

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_4_isog(R, A, C, coeff);
	oqs_sidh_cln16_j_inv(A, C, jinv);
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *) SharedSecretA); // Converting back to standard representation

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_ALICE * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) jinv, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) coeff, 5 * 2 * pwords);

	return Status;
}

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralSecretAgreement_B(const unsigned char *PrivateKeyB, const unsigned char *PublicKeyA, unsigned char *SharedSecretB, PCurveIsogenyStruct CurveIsogeny) { // Bob's ephemeral shared secret computation
	                                                                                                                                                                                              // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
	                                                                                                                                                                                              // Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^239.
	                                                                                                                                                                                              //         Alice's PublicKeyA consists of 3 elements in GF(p751^2).
	                                                                                                                                                                                              // Output: a shared secret SharedSecretB that consists of one element in GF(p751^2).
	                                                                                                                                                                                              // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_BOB], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_BOB];
	oqs_sidh_cln16_publickey_t *PublicKey = (oqs_sidh_cln16_publickey_t *) PublicKeyA;
	oqs_sidh_cln16_f2elm_t jinv, A, PKA[3], C = {0};
	SIDH_CRYPTO_STATUS Status = SIDH_CRYPTO_SUCCESS;

	if (PrivateKeyB == NULL || PublicKey == NULL || SharedSecretB == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[0], PKA[0]); // Extracting and converting Alice's public curve parameters to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[1], PKA[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKey)[2], PKA[2]);

	oqs_sidh_cln16_get_A(PKA[0], PKA[1], PKA[2], A, CurveIsogeny);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	Status = oqs_sidh_cln16_ladder_3_pt(PKA[0], PKA[1], PKA[2], (digit_t *) PrivateKeyB, SIDH_BOB, R, A, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		return Status;
	}

	index = 0;
	for (row = 1; row < SIDH_MAX_Bob; row++) {
		while (index < SIDH_MAX_Bob - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Bob[SIDH_MAX_Bob - index - row];
			oqs_sidh_cln16_xTPLe(R, R, A, C, (int) m);
			index += m;
		}
		oqs_sidh_cln16_get_3_isog(R, A, C);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_3_isog(R, pts[i]);
		}

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_3_isog(R, A, C);
	oqs_sidh_cln16_j_inv(A, C, jinv);
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *) SharedSecretB); // Converting back to standard representation

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_BOB * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) jinv, 2 * pwords);

	return Status;
}

///////////////////////////////////////////////////////////////////////////////////
///////////////          KEY EXCHANGE USING DECOMPRESSION           ///////////////

void oqs_sidh_cln16_PublicKeyCompression_A(const unsigned char *PublicKeyA, unsigned char *CompressedPKA, PCurveIsogenyStruct CurveIsogeny) { // Alice's public key compression
	                                                                                                                                          // It produces a compressed output that consists of three elements in Z_orderB and one field element
	                                                                                                                                          // Input : Alice's public key PublicKeyA, which consists of 3 elements in GF(p751^2).
	                                                                                                                                          // Output: a compressed value CompressedPKA that consists of three elements in Z_orderB and one element in GF(p751^2).
	                                                                                                                                          // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	oqs_sidh_cln16_point_full_proj_t P, Q, phP, phQ, phX;
	oqs_sidh_cln16_point_t R1, R2, phiP, phiQ;
	oqs_sidh_cln16_publickey_t PK;
	digit_t *comp = (digit_t *) CompressedPKA;
	digit_t inv[SIDH_NWORDS_ORDER];
	oqs_sidh_cln16_f2elm_t A, vec[4], Zinv[4];
	digit_t a0[SIDH_NWORDS_ORDER], b0[SIDH_NWORDS_ORDER], a1[SIDH_NWORDS_ORDER], b1[SIDH_NWORDS_ORDER];
	uint64_t Montgomery_Rprime[SIDH_NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
	uint64_t Montgomery_rprime[SIDH_NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
	unsigned int bit;

	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyA)[0], ((oqs_sidh_cln16_f2elm_t *) &PK)[0]); // Converting to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyA)[1], ((oqs_sidh_cln16_f2elm_t *) &PK)[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyA)[2], ((oqs_sidh_cln16_f2elm_t *) &PK)[2]);

	oqs_sidh_cln16_recover_y(PK, phP, phQ, phX, A, CurveIsogeny);
	oqs_sidh_cln16_generate_3_torsion_basis(A, P, Q, CurveIsogeny);
	oqs_sidh_cln16_fp2copy751(P->Z, vec[0]);
	oqs_sidh_cln16_fp2copy751(Q->Z, vec[1]);
	oqs_sidh_cln16_fp2copy751(phP->Z, vec[2]);
	oqs_sidh_cln16_fp2copy751(phQ->Z, vec[3]);
	oqs_sidh_cln16_mont_n_way_inv(vec, 4, Zinv);

	oqs_sidh_cln16_fp2mul751_mont(P->X, Zinv[0], R1->x);
	oqs_sidh_cln16_fp2mul751_mont(P->Y, Zinv[0], R1->y);
	oqs_sidh_cln16_fp2mul751_mont(Q->X, Zinv[1], R2->x);
	oqs_sidh_cln16_fp2mul751_mont(Q->Y, Zinv[1], R2->y);
	oqs_sidh_cln16_fp2mul751_mont(phP->X, Zinv[2], phiP->x);
	oqs_sidh_cln16_fp2mul751_mont(phP->Y, Zinv[2], phiP->y);
	oqs_sidh_cln16_fp2mul751_mont(phQ->X, Zinv[3], phiQ->x);
	oqs_sidh_cln16_fp2mul751_mont(phQ->Y, Zinv[3], phiQ->y);

	oqs_sidh_cln16_ph3(phiP, phiQ, R1, R2, A, (uint64_t *) a0, (uint64_t *) b0, (uint64_t *) a1, (uint64_t *) b1, CurveIsogeny);

	bit = oqs_sidh_cln16_mod3(a0);
	oqs_sidh_cln16_to_Montgomery_mod_order(a0, a0, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime); // Converting to Montgomery representation
	oqs_sidh_cln16_to_Montgomery_mod_order(a1, a1, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
	oqs_sidh_cln16_to_Montgomery_mod_order(b0, b0, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
	oqs_sidh_cln16_to_Montgomery_mod_order(b1, b1, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);

	if (bit != 0) { // Storing [b1*a0inv, a1*a0inv, b0*a0inv] and setting bit384 to 0
		oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(a0, inv, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(b0, inv, &comp[0], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(a1, inv, &comp[SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(b1, inv, &comp[2 * SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime); // Converting back from Montgomery representation
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[SIDH_NWORDS_ORDER], &comp[SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[2 * SIDH_NWORDS_ORDER], &comp[2 * SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		comp[3 * SIDH_NWORDS_ORDER - 1] &= (digit_t)(-1) >> 1;
	} else { // Storing [b1*b0inv, a1*b0inv, a0*b0inv] and setting bit384 to 1
		oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(b0, inv, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(a0, inv, &comp[0], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(a1, inv, &comp[SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(b1, inv, &comp[2 * SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime); // Converting back from Montgomery representation
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[SIDH_NWORDS_ORDER], &comp[SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(&comp[2 * SIDH_NWORDS_ORDER], &comp[2 * SIDH_NWORDS_ORDER], CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		comp[3 * SIDH_NWORDS_ORDER - 1] |= (digit_t) 1 << (sizeof(digit_t) * 8 - 1);
	}

	oqs_sidh_cln16_from_fp2mont(A, (oqs_sidh_cln16_felm_t *) &comp[3 * SIDH_NWORDS_ORDER]);
}

void oqs_sidh_cln16_PublicKeyADecompression_B(const unsigned char *SecretKeyB, const unsigned char *CompressedPKA, unsigned char *point_R, unsigned char *param_A, PCurveIsogenyStruct CurveIsogeny) { // Alice's public key value decompression computed by Bob
	                                                                                                                                                                                                   // Inputs: Bob's private key SecretKeyB, and
	                                                                                                                                                                                                   //         Alice's compressed public key data CompressedPKA, which consists of three elements in Z_orderB and one element in GF(p751^2),
	                                                                                                                                                                                                   // Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
	                                                                                                                                                                                                   // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	oqs_sidh_cln16_point_t R1, R2;
	oqs_sidh_cln16_point_proj_t *R = (oqs_sidh_cln16_point_proj_t *) point_R;
	oqs_sidh_cln16_point_full_proj_t P, Q;
	digit_t *comp = (digit_t *) CompressedPKA;
	digit_t *SKin = (digit_t *) SecretKeyB;
	oqs_sidh_cln16_f2elm_t A24, vec[2], invs[2], one = {0};
	oqs_sidh_cln16_felm_t *A = (oqs_sidh_cln16_felm_t *) param_A;
	digit_t t1[SIDH_NWORDS_ORDER], t2[SIDH_NWORDS_ORDER], t3[SIDH_NWORDS_ORDER], t4[SIDH_NWORDS_ORDER], vone[SIDH_NWORDS_ORDER] = {0};
	uint64_t Montgomery_Rprime[SIDH_NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
	uint64_t Montgomery_rprime[SIDH_NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
	unsigned int bit;

	vone[0] = 1;
	oqs_sidh_cln16_to_Montgomery_mod_order(vone, vone, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime); // Converting to Montgomery representation
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	oqs_sidh_cln16_to_fp2mont((oqs_sidh_cln16_felm_t *) &comp[3 * SIDH_NWORDS_ORDER], A); // Converting to Montgomery representation
	oqs_sidh_cln16_generate_3_torsion_basis(A, P, Q, CurveIsogeny);

	// Normalize basis points
	oqs_sidh_cln16_fp2copy751(P->Z, vec[0]);
	oqs_sidh_cln16_fp2copy751(Q->Z, vec[1]);
	oqs_sidh_cln16_mont_n_way_inv(vec, 2, invs);
	oqs_sidh_cln16_fp2mul751_mont(P->X, invs[0], R1->x);
	oqs_sidh_cln16_fp2mul751_mont(P->Y, invs[0], R1->y);
	oqs_sidh_cln16_fp2mul751_mont(Q->X, invs[1], R2->x);
	oqs_sidh_cln16_fp2mul751_mont(Q->Y, invs[1], R2->y);

	oqs_sidh_cln16_fp2add751(A, one, A24);
	oqs_sidh_cln16_fp2add751(A24, one, A24);
	oqs_sidh_cln16_fp2div2_751(A24, A24);
	oqs_sidh_cln16_fp2div2_751(A24, A24);

	bit = comp[3 * SIDH_NWORDS_ORDER - 1] >> (sizeof(digit_t) * 8 - 1);
	comp[3 * SIDH_NWORDS_ORDER - 1] &= (digit_t)(-1) >> 1;
	oqs_sidh_cln16_to_Montgomery_mod_order(SKin, t1, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime); // Converting to Montgomery representation
	oqs_sidh_cln16_to_Montgomery_mod_order(&comp[0], t2, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
	oqs_sidh_cln16_to_Montgomery_mod_order(&comp[SIDH_NWORDS_ORDER], t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
	oqs_sidh_cln16_to_Montgomery_mod_order(&comp[2 * SIDH_NWORDS_ORDER], t4, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);

	if (bit == 0) {
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t1, t3, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_mp_add(t3, vone, t3, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(t3, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t1, t4, t4, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_mp_add(t2, t4, t4, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t3, t4, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(t3, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime); // Converting back from Montgomery representation
		oqs_sidh_cln16_mont_twodim_scalarmult(t3, R1, R2, A, A24, P, CurveIsogeny);
	} else {
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t1, t4, t4, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_mp_add(t4, vone, t4, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_Montgomery_inversion_mod_order_bingcd(t4, t4, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime, (digit_t *) &Montgomery_Rprime);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t1, t3, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_mp_add(t2, t3, t3, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_Montgomery_multiply_mod_order(t3, t4, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime);
		oqs_sidh_cln16_from_Montgomery_mod_order(t3, t3, CurveIsogeny->Border, (digit_t *) &Montgomery_rprime); // Converting back from Montgomery representation
		oqs_sidh_cln16_mont_twodim_scalarmult(t3, R2, R1, A, A24, P, CurveIsogeny);
	}

	oqs_sidh_cln16_fp2copy751(P->X, R[0]->X);
	oqs_sidh_cln16_fp2copy751(P->Z, R[0]->Z);
}

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralSecretAgreement_Compression_A(const unsigned char *PrivateKeyA, const unsigned char *point_R, const unsigned char *param_A, unsigned char *SharedSecretA, PCurveIsogenyStruct CurveIsogeny) { // Alice's ephemeral shared secret computation
	                                                                                                                                                                                                                                     // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's decompressed data point_R and param_A
	                                                                                                                                                                                                                                     // Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372.
	                                                                                                                                                                                                                                     //         Bob's decompressed data consists of point_R in (X:Z) coordinates and the curve paramater param_A in GF(p751^2).
	                                                                                                                                                                                                                                     // Output: a shared secret SharedSecretA that consists of one element in GF(p751^2).
	                                                                                                                                                                                                                                     // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_ALICE], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_ALICE];
	oqs_sidh_cln16_f2elm_t jinv, coeff[5], A, C = {0};

	if (PrivateKeyA == NULL || SharedSecretA == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_fp2copy751((((oqs_sidh_cln16_point_proj_t *) point_R)[0])->X, R->X);
	oqs_sidh_cln16_fp2copy751((((oqs_sidh_cln16_point_proj_t *) point_R)[0])->Z, R->Z);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);
	oqs_sidh_cln16_first_4_isog(R, (oqs_sidh_cln16_felm_t *) param_A, A, C, CurveIsogeny);

	index = 0;
	for (row = 1; row < SIDH_MAX_Alice; row++) {
		while (index < SIDH_MAX_Alice - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Alice[SIDH_MAX_Alice - index - row];
			oqs_sidh_cln16_xDBLe(R, R, A, C, (int) (2 * m));
			index += m;
		}
		oqs_sidh_cln16_get_4_isog(R, A, C, coeff);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_4_isog(pts[i], coeff);
		}

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_4_isog(R, A, C, coeff);
	oqs_sidh_cln16_j_inv(A, C, jinv);
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *) SharedSecretA); // Converting back to standard representation

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_ALICE * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) jinv, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) coeff, 5 * 2 * pwords);

	return SIDH_CRYPTO_SUCCESS;
}

void oqs_sidh_cln16_PublicKeyCompression_B(const unsigned char *PublicKeyB, unsigned char *CompressedPKB, PCurveIsogenyStruct CurveIsogeny) { // Bob's public key compression
	                                                                                                                                          // It produces a compressed output that consists of three elements in Z_orderA and one field element
	                                                                                                                                          // Input : Bob's public key PublicKeyB, which consists of 3 elements in GF(p751^2).
	                                                                                                                                          // Output: a compressed value CompressedPKB that consists of three elements in Z_orderA and one element in GF(p751^2).
	                                                                                                                                          // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	oqs_sidh_cln16_point_full_proj_t P, Q, phP, phQ, phX;
	oqs_sidh_cln16_point_t R1, R2, phiP, phiQ;
	oqs_sidh_cln16_publickey_t PK;
	digit_t *comp = (digit_t *) CompressedPKB;
	digit_t inv[SIDH_NWORDS_ORDER];
	oqs_sidh_cln16_f2elm_t A, vec[4], Zinv[4];
	digit_t a0[SIDH_NWORDS_ORDER], b0[SIDH_NWORDS_ORDER], a1[SIDH_NWORDS_ORDER], b1[SIDH_NWORDS_ORDER], tmp[2 * SIDH_NWORDS_ORDER], mask = (digit_t)(-1);

	mask >>= (CurveIsogeny->owordbits - CurveIsogeny->oAbits);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyB)[0], ((oqs_sidh_cln16_f2elm_t *) &PK)[0]); // Converting to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyB)[1], ((oqs_sidh_cln16_f2elm_t *) &PK)[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *) PublicKeyB)[2], ((oqs_sidh_cln16_f2elm_t *) &PK)[2]);

	oqs_sidh_cln16_recover_y(PK, phP, phQ, phX, A, CurveIsogeny);
	oqs_sidh_cln16_generate_2_torsion_basis(A, P, Q, CurveIsogeny);
	oqs_sidh_cln16_fp2copy751(P->Z, vec[0]);
	oqs_sidh_cln16_fp2copy751(Q->Z, vec[1]);
	oqs_sidh_cln16_fp2copy751(phP->Z, vec[2]);
	oqs_sidh_cln16_fp2copy751(phQ->Z, vec[3]);
	oqs_sidh_cln16_mont_n_way_inv(vec, 4, Zinv);

	oqs_sidh_cln16_fp2mul751_mont(P->X, Zinv[0], R1->x);
	oqs_sidh_cln16_fp2mul751_mont(P->Y, Zinv[0], R1->y);
	oqs_sidh_cln16_fp2mul751_mont(Q->X, Zinv[1], R2->x);
	oqs_sidh_cln16_fp2mul751_mont(Q->Y, Zinv[1], R2->y);
	oqs_sidh_cln16_fp2mul751_mont(phP->X, Zinv[2], phiP->x);
	oqs_sidh_cln16_fp2mul751_mont(phP->Y, Zinv[2], phiP->y);
	oqs_sidh_cln16_fp2mul751_mont(phQ->X, Zinv[3], phiQ->x);
	oqs_sidh_cln16_fp2mul751_mont(phQ->Y, Zinv[3], phiQ->y);

	oqs_sidh_cln16_ph2(phiP, phiQ, R1, R2, A, (uint64_t *) a0, (uint64_t *) b0, (uint64_t *) a1, (uint64_t *) b1, CurveIsogeny);

	if ((a0[0] & 1) == 1) { // Storing [b1*a0inv, a1*a0inv, b0*a0inv] and setting bit384 to 0
		oqs_sidh_cln16_inv_mod_orderA(a0, inv);
		oqs_sidh_cln16_multiply(b0, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[0], SIDH_NWORDS_ORDER);
		comp[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_multiply(a1, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[SIDH_NWORDS_ORDER], SIDH_NWORDS_ORDER);
		comp[2 * SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_multiply(b1, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[2 * SIDH_NWORDS_ORDER], SIDH_NWORDS_ORDER);
		comp[3 * SIDH_NWORDS_ORDER - 1] &= mask;
	} else { // Storing [b1*b0inv, a1*b0inv, a0*b0inv] and setting bit384 to 1
		oqs_sidh_cln16_inv_mod_orderA(b0, inv);
		oqs_sidh_cln16_multiply(a0, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[0], SIDH_NWORDS_ORDER);
		comp[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_multiply(a1, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[SIDH_NWORDS_ORDER], SIDH_NWORDS_ORDER);
		comp[2 * SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_multiply(b1, inv, tmp, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_copy_words(tmp, &comp[2 * SIDH_NWORDS_ORDER], SIDH_NWORDS_ORDER);
		comp[3 * SIDH_NWORDS_ORDER - 1] &= mask;
		comp[3 * SIDH_NWORDS_ORDER - 1] |= (digit_t) 1 << (sizeof(digit_t) * 8 - 1);
	}

	oqs_sidh_cln16_from_fp2mont(A, (oqs_sidh_cln16_felm_t *) &comp[3 * SIDH_NWORDS_ORDER]); // Converting back from Montgomery representation
}

void oqs_sidh_cln16_PublicKeyBDecompression_A(const unsigned char *SecretKeyA, const unsigned char *CompressedPKB, unsigned char *point_R, unsigned char *param_A, PCurveIsogenyStruct CurveIsogeny) { // Bob's public key value decompression computed by Alice
	                                                                                                                                                                                                   // Inputs: Alice's private key SecretKeyA, and
	                                                                                                                                                                                                   //         Bob's compressed public key data CompressedPKB, which consists of three elements in Z_orderA and one element in GF(p751^2).
	                                                                                                                                                                                                   // Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
	                                                                                                                                                                                                   // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	oqs_sidh_cln16_point_t R1, R2;
	oqs_sidh_cln16_point_proj_t *R = (oqs_sidh_cln16_point_proj_t *) point_R;
	oqs_sidh_cln16_point_full_proj_t P, Q;
	digit_t *comp = (digit_t *) CompressedPKB;
	oqs_sidh_cln16_f2elm_t A24, vec[2], invs[2], one = {0};
	oqs_sidh_cln16_felm_t *A = (oqs_sidh_cln16_felm_t *) param_A;
	digit_t tmp1[2 * SIDH_NWORDS_ORDER], tmp2[2 * SIDH_NWORDS_ORDER], vone[2 * SIDH_NWORDS_ORDER] = {0}, mask = (digit_t)(-1);
	unsigned int bit;

	mask >>= (CurveIsogeny->owordbits - CurveIsogeny->oAbits);
	vone[0] = 1;
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	oqs_sidh_cln16_to_fp2mont((oqs_sidh_cln16_felm_t *) &comp[3 * SIDH_NWORDS_ORDER], A); // Converting to Montgomery representation
	oqs_sidh_cln16_generate_2_torsion_basis(A, P, Q, CurveIsogeny);

	// normalize basis points
	oqs_sidh_cln16_fp2copy751(P->Z, vec[0]);
	oqs_sidh_cln16_fp2copy751(Q->Z, vec[1]);
	oqs_sidh_cln16_mont_n_way_inv(vec, 2, invs);
	oqs_sidh_cln16_fp2mul751_mont(P->X, invs[0], R1->x);
	oqs_sidh_cln16_fp2mul751_mont(P->Y, invs[0], R1->y);
	oqs_sidh_cln16_fp2mul751_mont(Q->X, invs[1], R2->x);
	oqs_sidh_cln16_fp2mul751_mont(Q->Y, invs[1], R2->y);

	oqs_sidh_cln16_fp2add751(A, one, A24);
	oqs_sidh_cln16_fp2add751(A24, one, A24);
	oqs_sidh_cln16_fp2div2_751(A24, A24);
	oqs_sidh_cln16_fp2div2_751(A24, A24);

	bit = comp[3 * SIDH_NWORDS_ORDER - 1] >> (sizeof(digit_t) * 8 - 1);
	comp[3 * SIDH_NWORDS_ORDER - 1] &= (digit_t)(-1) >> 1;

	if (bit == 0) {
		oqs_sidh_cln16_multiply((digit_t *) SecretKeyA, &comp[SIDH_NWORDS_ORDER], tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_mp_add(tmp1, vone, tmp1, SIDH_NWORDS_ORDER);
		tmp1[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_inv_mod_orderA(tmp1, tmp2);
		oqs_sidh_cln16_multiply((digit_t *) SecretKeyA, &comp[2 * SIDH_NWORDS_ORDER], tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_mp_add(&comp[0], tmp1, tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_multiply(tmp1, tmp2, vone, SIDH_NWORDS_ORDER);
		vone[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_mont_twodim_scalarmult(vone, R1, R2, A, A24, P, CurveIsogeny);
	} else {
		oqs_sidh_cln16_multiply((digit_t *) SecretKeyA, &comp[2 * SIDH_NWORDS_ORDER], tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_mp_add(tmp1, vone, tmp1, SIDH_NWORDS_ORDER);
		tmp1[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_inv_mod_orderA(tmp1, tmp2);
		oqs_sidh_cln16_multiply((digit_t *) SecretKeyA, &comp[SIDH_NWORDS_ORDER], tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_mp_add(&comp[0], tmp1, tmp1, SIDH_NWORDS_ORDER);
		oqs_sidh_cln16_multiply(tmp1, tmp2, vone, SIDH_NWORDS_ORDER);
		vone[SIDH_NWORDS_ORDER - 1] &= mask;
		oqs_sidh_cln16_mont_twodim_scalarmult(vone, R2, R1, A, A24, P, CurveIsogeny);
	}

	oqs_sidh_cln16_fp2copy751(P->X, R[0]->X);
	oqs_sidh_cln16_fp2copy751(P->Z, R[0]->Z);
}

SIDH_CRYPTO_STATUS oqs_sidh_cln16_EphemeralSecretAgreement_Compression_B(const unsigned char *PrivateKeyB, const unsigned char *point_R, const unsigned char *param_A, unsigned char *SharedSecretB, PCurveIsogenyStruct CurveIsogeny) { // Bob's ephemeral shared secret computation
	                                                                                                                                                                                                                                     // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's decompressed data point_R and param_A
	                                                                                                                                                                                                                                     // Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^239.
	                                                                                                                                                                                                                                     //         Alice's decompressed data consists of point_R in (X:Z) coordinates and the curve paramater param_A in GF(p751^2).
	                                                                                                                                                                                                                                     // Output: a shared secret SharedSecretB that consists of one element in GF(p751^2).
	                                                                                                                                                                                                                                     // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_BOB], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_BOB];
	oqs_sidh_cln16_f2elm_t jinv, A, C = {0};

	if (PrivateKeyB == NULL || SharedSecretB == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_fp2copy751((((oqs_sidh_cln16_point_proj_t *) point_R)[0])->X, R->X);
	oqs_sidh_cln16_fp2copy751((((oqs_sidh_cln16_point_proj_t *) point_R)[0])->Z, R->Z);
	oqs_sidh_cln16_fp2copy751((oqs_sidh_cln16_felm_t *) param_A, A);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	index = 0;
	for (row = 1; row < SIDH_MAX_Bob; row++) {
		while (index < SIDH_MAX_Bob - row) {
			oqs_sidh_cln16_fp2copy751(R->X, pts[npts]->X);
			oqs_sidh_cln16_fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Bob[SIDH_MAX_Bob - index - row];
			oqs_sidh_cln16_xTPLe(R, R, A, C, (int) m);
			index += m;
		}
		oqs_sidh_cln16_get_3_isog(R, A, C);

		for (i = 0; i < npts; i++) {
			oqs_sidh_cln16_eval_3_isog(R, pts[i]);
		}

		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->X, R->X);
		oqs_sidh_cln16_fp2copy751(pts[npts - 1]->Z, R->Z);
		index = pts_index[npts - 1];
		npts -= 1;
	}

	oqs_sidh_cln16_get_3_isog(R, A, C);
	oqs_sidh_cln16_j_inv(A, C, jinv);
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *) SharedSecretB); // Converting back to standard representation

	// Cleanup:
	oqs_sidh_cln16_clear_words((void *) R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) pts, SIDH_MAX_INT_POINTS_BOB * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *) jinv, 2 * pwords);

	return SIDH_CRYPTO_SUCCESS;
}
