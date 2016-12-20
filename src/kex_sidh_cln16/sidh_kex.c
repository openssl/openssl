/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: isogeny-based key exchange
*
*********************************************************************************************/

#include "SIDH_internal.h"

extern const unsigned int splits_Alice[SIDH_MAX_Alice];
extern const unsigned int splits_Bob[SIDH_MAX_Bob];

#ifdef SIDH_ASM
#include "AMD64/fp_x64.c"
#else
#include "generic/fp_generic.c"
#endif

SIDH_CRYPTO_STATUS oqs_sidh_cln16_KeyGeneration_A(unsigned char *pPrivateKeyA, unsigned char *pPublicKeyA, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Alice's key-pair generation
	// It produces a private key pPrivateKeyA and computes the public key pPublicKeyA.
	// The private key is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
	// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	oqs_sidh_cln16_point_basefield_t P;
	oqs_sidh_cln16_point_proj_t R, phiP = oqs_sidh_cln16_point_proj_t_EMPTY, phiQ = oqs_sidh_cln16_point_proj_t_EMPTY, phiD = oqs_sidh_cln16_point_proj_t_EMPTY, pts[SIDH_MAX_INT_POINTS_ALICE];
	oqs_sidh_cln16_publickey_t *PublicKeyA = (oqs_sidh_cln16_publickey_t *)pPublicKeyA;
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_ALICE], npts = 0;
	oqs_sidh_cln16_f2elm_t coeff[5], A = { {0} }, C = { {0} }, Aout, Cout;
	SIDH_CRYPTO_STATUS Status;

	if (pPrivateKeyA == NULL || pPublicKeyA == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	// Choose a random even number in the range [2, oA-2] as secret key for Alice
	Status = oqs_sidh_cln16_random_mod_order((digit_t *)pPrivateKeyA, SIDH_ALICE, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)pPrivateKeyA, owords);
		return Status;
	}

	oqs_sidh_cln16_to_mont((digit_t *)CurveIsogeny->PA, (digit_t *)P);                             // Conversion of Alice's generators to Montgomery representation
	oqs_sidh_cln16_to_mont(((digit_t *)CurveIsogeny->PA) + NWORDS_FIELD, ((digit_t *)P) + NWORDS_FIELD);

	Status = oqs_sidh_cln16_secret_pt(P, (digit_t *)pPrivateKeyA, SIDH_ALICE, R, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)pPrivateKeyA, owords);
		return Status;
	}

	oqs_sidh_cln16_copy_words((digit_t *)CurveIsogeny->PB, (digit_t *)phiP, pwords);               // Copy X-coordinates from Bob's public parameters, set Z <- 1
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, (digit_t *)phiP->Z);
	oqs_sidh_cln16_to_mont((digit_t *)phiP, (digit_t *)phiP);
	oqs_sidh_cln16_copy_words((digit_t *)phiP, (digit_t *)phiQ, pwords);                           // QB = (-XPB:1)
	oqs_sidh_cln16_fpneg751(phiQ->X[0]);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, (digit_t *)phiQ->Z);
	oqs_sidh_cln16_distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DB = (x(QB-PB),z(QB-PB))

	oqs_sidh_cln16_fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
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
			oqs_sidh_cln16_xDBLe(R, R, A, C, (int)(2 * m));
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

	oqs_sidh_cln16_from_fp2mont(phiP->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[0]);                              // Converting back to standard representation
	oqs_sidh_cln16_from_fp2mont(phiQ->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[1]);
	oqs_sidh_cln16_from_fp2mont(phiD->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[2]);

// Cleanup:
	oqs_sidh_cln16_clear_words((void *)R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiP, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiQ, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiD, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)pts, SIDH_MAX_INT_POINTS_ALICE * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)coeff, 5 * 2 * pwords);

	return Status;
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_KeyGeneration_B(unsigned char *pPrivateKeyB, unsigned char *pPublicKeyB, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Bob's key-pair generation
	// It produces a private key pPrivateKeyB and computes the public key pPublicKeyB.
	// The private key is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
	// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	oqs_sidh_cln16_point_basefield_t P;
	oqs_sidh_cln16_point_proj_t R, phiP = oqs_sidh_cln16_point_proj_t_EMPTY, phiQ = oqs_sidh_cln16_point_proj_t_EMPTY, phiD = oqs_sidh_cln16_point_proj_t_EMPTY, pts[SIDH_MAX_INT_POINTS_BOB];
	oqs_sidh_cln16_publickey_t *PublicKeyB = (oqs_sidh_cln16_publickey_t *)pPublicKeyB;
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_BOB], npts = 0;
	oqs_sidh_cln16_f2elm_t A = { {0} }, C = { {0} };
	SIDH_CRYPTO_STATUS Status;

	if (pPrivateKeyB == NULL || pPublicKeyB == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	// Choose a random number equivalent to 0 (mod 3) in the range [3, oB-3] as secret key for Bob
	Status = oqs_sidh_cln16_random_mod_order((digit_t *)pPrivateKeyB, SIDH_BOB, CurveIsogeny, rand);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)pPrivateKeyB, owords);
		return Status;
	}

	oqs_sidh_cln16_to_mont((digit_t *)CurveIsogeny->PB, (digit_t *)P);                             // Conversion of Bob's generators to Montgomery representation
	oqs_sidh_cln16_to_mont(((digit_t *)CurveIsogeny->PB) + NWORDS_FIELD, ((digit_t *)P) + NWORDS_FIELD);

	Status = oqs_sidh_cln16_secret_pt(P, (digit_t *)pPrivateKeyB, SIDH_BOB, R, CurveIsogeny);
	if (Status != SIDH_CRYPTO_SUCCESS) {
		oqs_sidh_cln16_clear_words((void *)pPrivateKeyB, owords);
		return Status;
	}

	oqs_sidh_cln16_copy_words((digit_t *)CurveIsogeny->PA, (digit_t *)phiP, pwords);               // Copy X-coordinates from Alice's public parameters, set Z <- 1
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, (digit_t *)phiP->Z);
	oqs_sidh_cln16_to_mont((digit_t *)phiP, (digit_t *)phiP);                                      // Conversion to Montgomery representation
	oqs_sidh_cln16_copy_words((digit_t *)phiP, (digit_t *)phiQ, pwords);                           // QA = (-XPA:1)
	oqs_sidh_cln16_fpneg751(phiQ->X[0]);
	oqs_sidh_cln16_fpcopy751((digit_t *)CurveIsogeny->Montgomery_one, (digit_t *)phiQ->Z);
	oqs_sidh_cln16_distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DA = (x(QA-PA),z(QA-PA))

	oqs_sidh_cln16_fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
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
			oqs_sidh_cln16_xTPLe(R, R, A, C, (int)m);
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

	oqs_sidh_cln16_from_fp2mont(phiP->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[0]);                              // Converting back to standard representation
	oqs_sidh_cln16_from_fp2mont(phiQ->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[1]);
	oqs_sidh_cln16_from_fp2mont(phiD->X, ((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[2]);

// Cleanup:
	oqs_sidh_cln16_clear_words((void *)R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiP, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiQ, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)phiD, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)pts, SIDH_MAX_INT_POINTS_BOB * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)C, 2 * pwords);

	return Status;
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_SecretAgreement_A(unsigned char *pPrivateKeyA, unsigned char *pPublicKeyB, unsigned char *pSharedSecretA, bool validate, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Alice's shared secret generation
	// It produces a shared secret key pSharedSecretA using her secret key pPrivateKeyA and Bob's public key pPublicKeyB
	// Inputs: Alice's pPrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
	//         Bob's pPublicKeyB consists of 3 elements in GF(p751^2), i.e., 564 bytes.
	//         "validate" flag that indicates if Alice must validate Bob's public key.
	// Output: a shared secret pSharedSecretA that consists of one element in GF(p751^2), i.e., 1502 bits in total.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_ALICE], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_ALICE];
	oqs_sidh_cln16_publickey_t *PublicKeyB = (oqs_sidh_cln16_publickey_t *)pPublicKeyB;
	oqs_sidh_cln16_f2elm_t jinv, coeff[5], PKB[3], A, C = { {0} };
	bool valid_PublicKey = false;
	SIDH_CRYPTO_STATUS Status;

	if (pPrivateKeyA == NULL || pPublicKeyB == NULL || pSharedSecretA == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[0], PKB[0]);   // Extracting and converting Bob's public curve parameters to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[1], PKB[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyB)[2], PKB[2]);

	oqs_sidh_cln16_get_A(PKB[0], PKB[1], PKB[2], A, CurveIsogeny);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	if (validate == true) {                           // Alice validating Bob's public key
		Status = oqs_sidh_cln16_Validate_PKB(A, &PKB[0], &valid_PublicKey, CurveIsogeny, rand);
		if (Status != SIDH_CRYPTO_SUCCESS) {
			return Status;
		}
		if (valid_PublicKey != true) {
			Status = SIDH_CRYPTO_ERROR_PUBLIC_KEY_VALIDATION;
			return Status;
		}
	}

	Status = oqs_sidh_cln16_ladder_3_pt(PKB[0], PKB[1], PKB[2], (digit_t *)pPrivateKeyA, SIDH_ALICE, R, A, CurveIsogeny);
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
			oqs_sidh_cln16_xDBLe(R, R, A, C, (int)(2 * m));
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
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *)pSharedSecretA);     // Converting back to standard representation

// Cleanup:
	oqs_sidh_cln16_clear_words((void *)R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)pts, SIDH_MAX_INT_POINTS_ALICE * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)jinv, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)coeff, 5 * 2 * pwords);

	return Status;
}


SIDH_CRYPTO_STATUS oqs_sidh_cln16_SecretAgreement_B(unsigned char *pPrivateKeyB, unsigned char *pPublicKeyA, unsigned char *pSharedSecretB, bool validate, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand) {
	// Bob's shared secret generation
	// It produces a shared secret key pSharedSecretB using his secret key pPrivateKeyB and Alice's public key pPublicKeyA
	// Inputs: Bob's pPrivateKeyB is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
	//         Alice's pPublicKeyA consists of 3 elements in GF(p751^2), i.e., 564 bytes.
	//         "validate" flag that indicates if Bob must validate Alice's public key.
	// Output: a shared secret pSharedSecretB that consists of one element in GF(p751^2), i.e., 1502 bits in total.
	// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	unsigned int i, row, m, index = 0, pts_index[SIDH_MAX_INT_POINTS_BOB], npts = 0;
	oqs_sidh_cln16_point_proj_t R, pts[SIDH_MAX_INT_POINTS_BOB];
	oqs_sidh_cln16_publickey_t *PublicKeyA = (oqs_sidh_cln16_publickey_t *)pPublicKeyA;
	oqs_sidh_cln16_f2elm_t jinv, A, PKA[3], C = { {0} };
	bool valid_PublicKey = false;
	SIDH_CRYPTO_STATUS Status;

	if (pPrivateKeyB == NULL || pPublicKeyA == NULL || pSharedSecretB == NULL || oqs_sidh_cln16_is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return SIDH_CRYPTO_ERROR_INVALID_PARAMETER;
	}

	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[0], PKA[0]);   // Extracting and converting Alice's public curve parameters to Montgomery representation
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[1], PKA[1]);
	oqs_sidh_cln16_to_fp2mont(((oqs_sidh_cln16_f2elm_t *)PublicKeyA)[2], PKA[2]);

	oqs_sidh_cln16_get_A(PKA[0], PKA[1], PKA[2], A, CurveIsogeny);
	oqs_sidh_cln16_fpcopy751(CurveIsogeny->C, C[0]);
	oqs_sidh_cln16_to_mont(C[0], C[0]);

	if (validate == true) {                           // Bob validating Alice's public key
		Status = oqs_sidh_cln16_Validate_PKA(A, &PKA[0], &valid_PublicKey, CurveIsogeny, rand);
		if (Status != SIDH_CRYPTO_SUCCESS) {
			return Status;
		}
		if (valid_PublicKey != true) {
			Status = SIDH_CRYPTO_ERROR_PUBLIC_KEY_VALIDATION;
			return Status;
		}
	}

	Status = oqs_sidh_cln16_ladder_3_pt(PKA[0], PKA[1], PKA[2], (digit_t *)pPrivateKeyB, SIDH_BOB, R, A, CurveIsogeny);
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
			oqs_sidh_cln16_xTPLe(R, R, A, C, (int)m);
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
	oqs_sidh_cln16_from_fp2mont(jinv, (oqs_sidh_cln16_felm_t *)pSharedSecretB);     // Converting back to standard representation

// Cleanup:
	oqs_sidh_cln16_clear_words((void *)R, 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)pts, SIDH_MAX_INT_POINTS_BOB * 2 * 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)A, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)C, 2 * pwords);
	oqs_sidh_cln16_clear_words((void *)jinv, 2 * pwords);

	return Status;
}
