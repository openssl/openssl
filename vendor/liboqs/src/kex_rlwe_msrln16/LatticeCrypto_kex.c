/****************************************************************************************
 * LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
 *
 *    Copyright (c) Microsoft Corporation. All rights reserved.
 *
 *
 * Abstract: Ring-LWE key exchange
 *           The implementation is based on the instantiation of Peikert's key exchange [1]
 *           due to Alkim, Ducas, Poppelmann and Schwabe [2].
 *
 * [1] C. Peikert, "Lattice cryptography for the internet", in Post-Quantum Cryptography -
 *     6th International Workshop (PQCrypto 2014), LNCS 8772, pp. 197-219. Springer, 2014.
 * [2] E. Alkim, L. Ducas, T. Pöppelmann and P. Schwabe, "Post-quantum key exchange - a new
 *     hope", IACR Cryptology ePrint Archive, Report 2015/1092, 2015.
 *
 ******************************************************************************************/

#include "LatticeCrypto_priv.h"
#include "oqs/rand.h"
#include <oqs/sha3.h>

extern const int32_t psi_rev_ntt1024_12289[1024];
extern const int32_t omegainv_rev_ntt1024_12289[1024];
extern const int32_t omegainv10N_rev_ntt1024_12289;
extern const int32_t Ninv11_ntt1024_12289;

// import external code
#ifdef RLWE_ASM_AVX2
#include "AMD64/consts.c"
#include "AMD64/ntt_x64.c"
#else
#include "generic/ntt.c"
#endif


__inline void oqs_rlwe_msrln16_clear_words(void *mem, digit_t nwords) {
	// Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
	// This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
	unsigned int i;
	volatile digit_t *v = mem;

	for (i = 0; i < nwords; i++) {
		v[i] = 0;
	}
}

void oqs_rlwe_msrln16_encode_A(const uint32_t *pk, const unsigned char *seed, unsigned char *m) {
	// Alice's message encoding
	unsigned int i = 0, j;
#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_encode_asm(pk, m);
	i = 1792;
#else
	for (j = 0; j < 1024; j += 4) {
		m[i]   = (unsigned char)(pk[j] & 0xFF);
		m[i + 1] = (unsigned char)((pk[j] >> 8) | ((pk[j + 1] & 0x03) << 6));
		m[i + 2] = (unsigned char)((pk[j + 1] >> 2) & 0xFF);
		m[i + 3] = (unsigned char)((pk[j + 1] >> 10) | ((pk[j + 2] & 0x0F) << 4));
		m[i + 4] = (unsigned char)((pk[j + 2] >> 4) & 0xFF);
		m[i + 5] = (unsigned char)((pk[j + 2] >> 12) | ((pk[j + 3] & 0x3F) << 2));
		m[i + 6] = (unsigned char)(pk[j + 3] >> 6);
		i += 7;
	}
#endif

	for (j = 0; j < 32; j++) {
		m[i + j] = seed[j];
	}
}


void oqs_rlwe_msrln16_decode_A(const unsigned char *m, uint32_t *pk, unsigned char *seed) {
	// Alice's message decoding
	unsigned int i = 0, j;

#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_decode_asm(m, pk);
	i = 1792;
#else
	for (j = 0; j < 1024; j += 4) {
		pk[j]   = ((uint32_t)m[i] | (((uint32_t)m[i + 1] & 0x3F) << 8));
		pk[j + 1] = (((uint32_t)m[i + 1] >> 6) | ((uint32_t)m[i + 2] << 2) | (((uint32_t)m[i + 3] & 0x0F) << 10));
		pk[j + 2] = (((uint32_t)m[i + 3] >> 4) | ((uint32_t)m[i + 4] << 4) | (((uint32_t)m[i + 5] & 0x03) << 12));
		pk[j + 3] = (((uint32_t)m[i + 5] >> 2) | ((uint32_t)m[i + 6] << 6));
		i += 7;
	}
#endif

	for (j = 0; j < 32; j++) {
		seed[j] = m[i + j];
	}
}


void oqs_rlwe_msrln16_encode_B(const uint32_t *pk, const uint32_t *rvec, unsigned char *m) {
	// Bob's message encoding
	unsigned int i = 0, j;

#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_encode_asm(pk, m);
#else
	for (j = 0; j < 1024; j += 4) {
		m[i]   = (unsigned char)(pk[j] & 0xFF);
		m[i + 1] = (unsigned char)((pk[j] >> 8) | ((pk[j + 1] & 0x03) << 6));
		m[i + 2] = (unsigned char)((pk[j + 1] >> 2) & 0xFF);
		m[i + 3] = (unsigned char)((pk[j + 1] >> 10) | ((pk[j + 2] & 0x0F) << 4));
		m[i + 4] = (unsigned char)((pk[j + 2] >> 4) & 0xFF);
		m[i + 5] = (unsigned char)((pk[j + 2] >> 12) | ((pk[j + 3] & 0x3F) << 2));
		m[i + 6] = (unsigned char)(pk[j + 3] >> 6);
		i += 7;
	}
#endif

	i = 0;
	for (j = 0; j < 1024 / 4; j++) {
		m[1792 + j] = (unsigned char)(rvec[i] | (rvec[i + 1] << 2) | (rvec[i + 2] << 4) | (rvec[i + 3] << 6));
		i += 4;
	}
}


void oqs_rlwe_msrln16_decode_B(unsigned char *m, uint32_t *pk, uint32_t *rvec) {
	// Bob's message decoding
	unsigned int i = 0, j;

#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_decode_asm(m, pk);
	i = 1792;
#else
	for (j = 0; j < 1024; j += 4) {
		pk[j]   = ((uint32_t)m[i] | (((uint32_t)m[i + 1] & 0x3F) << 8));
		pk[j + 1] = (((uint32_t)m[i + 1] >> 6) | ((uint32_t)m[i + 2] << 2) | (((uint32_t)m[i + 3] & 0x0F) << 10));
		pk[j + 2] = (((uint32_t)m[i + 3] >> 4) | ((uint32_t)m[i + 4] << 4) | (((uint32_t)m[i + 5] & 0x03) << 12));
		pk[j + 3] = (((uint32_t)m[i + 5] >> 2) | ((uint32_t)m[i + 6] << 6));
		i += 7;
	}
#endif

	i = 0;
	for (j = 0; j < 1024 / 4; j++) {
		rvec[i]   = (uint32_t)(m[1792 + j] & 0x03);
		rvec[i + 1] = (uint32_t)((m[1792 + j] >> 2) & 0x03);
		rvec[i + 2] = (uint32_t)((m[1792 + j] >> 4) & 0x03);
		rvec[i + 3] = (uint32_t)(m[1792 + j] >> 6);
		i += 4;
	}
}


static __inline uint32_t Abs(int32_t value) {
	// Compute absolute value
	uint32_t mask;

	mask = (uint32_t)(value >> 31);
	return ((mask ^ value) - mask);
}


CRYPTO_STATUS oqs_rlwe_msrln16_HelpRec(const uint32_t *x, uint32_t *rvec, OQS_RAND *rand) {
	// Reconciliation helper
	unsigned int i, j, norm;
	unsigned char bit, random_bits[32];
	uint32_t v0[4], v1[4];
	// OQS integration note: call to aux API replaced with direct call to OQS_RAND
	rand->rand_n(rand, random_bits, 32);

#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_helprec_asm(x, rvec, random_bits);
#else
	for (i = 0; i < 256; i++) {
		bit = 1 & (random_bits[i >> 3] >> (i & 0x07));
		rvec[i]     = (x[i]     << 1) - bit;
		rvec[i + 256] = (x[i + 256] << 1) - bit;
		rvec[i + 512] = (x[i + 512] << 1) - bit;
		rvec[i + 768] = (x[i + 768] << 1) - bit;

		norm = 0;
		v0[0] = 4;
		v0[1] = 4;
		v0[2] = 4;
		v0[3] = 4;
		v1[0] = 3;
		v1[1] = 3;
		v1[2] = 3;
		v1[3] = 3;
		for (j = 0; j < 4; j++) {
			v0[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_Q4 ) >> 31;
			v0[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_3Q4) >> 31;
			v0[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_5Q4) >> 31;
			v0[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_7Q4) >> 31;
			v1[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_Q2 ) >> 31;
			v1[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_Q  ) >> 31;
			v1[j] -= (rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_3Q2) >> 31;
			norm += Abs(2 * rvec[i + 256 * j] - OQS_RLWE_MSRLN16_PARAMETER_Q * v0[j]);
		}

		norm = (uint32_t)((int32_t)(norm - OQS_RLWE_MSRLN16_PARAMETER_Q) >> 31);    // If norm < q then norm = 0xff...ff, else norm = 0
		v0[0] = (norm & (v0[0] ^ v1[0])) ^ v1[0];
		v0[1] = (norm & (v0[1] ^ v1[1])) ^ v1[1];
		v0[2] = (norm & (v0[2] ^ v1[2])) ^ v1[2];
		v0[3] = (norm & (v0[3] ^ v1[3])) ^ v1[3];
		rvec[i]     = (v0[0] - v0[3]) & 0x03;
		rvec[i + 256] = (v0[1] - v0[3]) & 0x03;
		rvec[i + 512] = (v0[2] - v0[3]) & 0x03;
		rvec[i + 768] = ((v0[3] << 1) + (1 & ~norm)) & 0x03;
	}
#endif

	return CRYPTO_SUCCESS;
}


static __inline uint32_t LDDecode(int32_t *t) {
	// Low-density decoding
	unsigned int i, norm = 0;
	uint32_t mask1, mask2, value;
	int32_t cneg = -8 * OQS_RLWE_MSRLN16_PARAMETER_Q;

	for (i = 0; i < 4; i++) {
		mask1 = t[i] >> 31;                                    // If t[i] < 0 then mask2 = 0xff...ff, else mask2 = 0
		mask2 = (4 * OQS_RLWE_MSRLN16_PARAMETER_Q - (int32_t)Abs(t[i])) >> 31;  // If 4*PARAMETER_Q > Abs(t[i]) then mask2 = 0, else mask2 = 0xff...ff

		value = ((mask1 & (8 * OQS_RLWE_MSRLN16_PARAMETER_Q ^ cneg)) ^ cneg);
		norm += Abs(t[i] + (mask2 & value));
	}

	return ((8 * OQS_RLWE_MSRLN16_PARAMETER_Q - norm) >> 31) ^ 1;               // If norm < PARAMETER_Q then return 1, else return 0
}


void oqs_rlwe_msrln16_Rec(const uint32_t *x, const uint32_t *rvec, unsigned char *key) {
	// Reconciliation


#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_rec_asm(x, rvec, key);
#else
	unsigned int i;
	uint32_t t[4];

	for (i = 0; i < 32; i++) {
		key[i] = 0;
	}
	for (i = 0; i < 256; i++) {
		t[0] = 8 * x[i]     - (2 * rvec[i] + rvec[i + 768]) * OQS_RLWE_MSRLN16_PARAMETER_Q;
		t[1] = 8 * x[i + 256] - (2 * rvec[i + 256] + rvec[i + 768]) * OQS_RLWE_MSRLN16_PARAMETER_Q;
		t[2] = 8 * x[i + 512] - (2 * rvec[i + 512] + rvec[i + 768]) * OQS_RLWE_MSRLN16_PARAMETER_Q;
		t[3] = 8 * x[i + 768] - (rvec[i + 768]) * OQS_RLWE_MSRLN16_PARAMETER_Q;

		key[i >> 3] |= (unsigned char)LDDecode((int32_t *)t) << (i & 0x07);
	}
#endif
}


CRYPTO_STATUS oqs_rlwe_msrln16_get_error(int32_t *e, OQS_RAND *rand) {
	// Error sampling
	unsigned char stream[3 * OQS_RLWE_MSRLN16_PARAMETER_N];
	uint32_t *pstream = (uint32_t *)&stream;
	uint32_t acc1, acc2, temp;
	uint8_t *pacc1 = (uint8_t *)&acc1, *pacc2 = (uint8_t *)&acc2;
	unsigned int i, j;

	// OQS integration note: call to aux API replaced with direct call to OQS_RAND
	rand->rand_n(rand, stream, 3 * OQS_RLWE_MSRLN16_PARAMETER_N);

#if defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_error_sampling_asm(stream, e);
#else
	for (i = 0; i < OQS_RLWE_MSRLN16_PARAMETER_N / 4; i++) {
		acc1 = 0;
		acc2 = 0;
		for (j = 0; j < 8; j++) {
			acc1 += (pstream[i] >> j) & 0x01010101;
			acc2 += (pstream[i + OQS_RLWE_MSRLN16_PARAMETER_N / 4] >> j) & 0x01010101;
		}
		for (j = 0; j < 4; j++) {
			temp = pstream[i + 2 * OQS_RLWE_MSRLN16_PARAMETER_N / 4] >> j;
			acc1 += temp & 0x01010101;
			acc2 += (temp >> 4) & 0x01010101;
		}
		e[2 * i]   = pacc1[0] - pacc1[1];
		e[2 * i + 1] = pacc1[2] - pacc1[3];
		e[2 * i + OQS_RLWE_MSRLN16_PARAMETER_N / 2]   = pacc2[0] - pacc2[1];
		e[2 * i + OQS_RLWE_MSRLN16_PARAMETER_N / 2 + 1] = pacc2[2] - pacc2[3];
	}
#endif

	return CRYPTO_SUCCESS;
}

CRYPTO_STATUS oqs_rlwe_msrln16_generate_a(uint32_t *a, const unsigned char *seed) {
	// Generation of parameter a
	// OQS integration note: call to aux API replaced with direct call to shake128
	unsigned int pos = 0, ctr = 0;
	uint16_t val;
	unsigned int nblocks = 16;
	uint8_t buf[OQS_SHA3_SHAKE128_RATE * 16];
	uint64_t state[OQS_SHA3_STATESIZE];
	OQS_SHA3_shake128_absorb(state, seed, OQS_RLWE_MSRLN16_SEED_BYTES);
	OQS_SHA3_shake128_squeezeblocks((unsigned char *)buf, nblocks, state);

	while (ctr < OQS_RLWE_MSRLN16_PARAMETER_N) {
		val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		if (val < OQS_RLWE_MSRLN16_PARAMETER_Q) {
			a[ctr++] = val;
		}
		pos += 2;
		if (pos > OQS_SHA3_SHAKE128_RATE * nblocks - 2) {
			nblocks = 1;
			OQS_SHA3_shake128_squeezeblocks((unsigned char *)buf, nblocks, state);
			pos = 0;
		}
	}

	return CRYPTO_SUCCESS;
}


CRYPTO_STATUS oqs_rlwe_msrln16_KeyGeneration_A(int32_t *SecretKeyA, unsigned char *PublicKeyA, OQS_RAND *rand) {
	// Alice's key generation
	// It produces a private key SecretKeyA and computes the public key PublicKeyA.
	// Outputs: the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
	//          the public key PublicKeyA that occupies 1824 bytes
	// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
	uint32_t a[OQS_RLWE_MSRLN16_PARAMETER_N];
	int32_t e[OQS_RLWE_MSRLN16_PARAMETER_N];
	unsigned char seed[OQS_RLWE_MSRLN16_SEED_BYTES];
	CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

	rand->rand_n(rand, seed, OQS_RLWE_MSRLN16_SEED_BYTES);
	Status = oqs_rlwe_msrln16_generate_a(a, seed);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	Status = oqs_rlwe_msrln16_get_error(SecretKeyA, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	Status = oqs_rlwe_msrln16_get_error(e, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	oqs_rlwe_msrln16_NTT_CT_std2rev_12289(SecretKeyA, psi_rev_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_NTT_CT_std2rev_12289(e, psi_rev_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_smul(e, 3, OQS_RLWE_MSRLN16_PARAMETER_N);

	oqs_rlwe_msrln16_pmuladd((int32_t *)a, SecretKeyA, e, (int32_t *)a, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_correction((int32_t *)a, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_encode_A(a, seed, PublicKeyA);

cleanup:
	oqs_rlwe_msrln16_clear_words((void *)e, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));

	return Status;
}


CRYPTO_STATUS oqs_rlwe_msrln16_SecretAgreement_B(unsigned char *PublicKeyA, unsigned char *SharedSecretB, unsigned char *PublicKeyB, OQS_RAND *rand) {
	// Bob's key generation and shared secret computation
	// It produces a private key and computes the public key PublicKeyB. In combination with Alice's public key PublicKeyA, it computes
	// the shared secret SharedSecretB.
	// Input:   Alice's public key PublicKeyA that consists of 1824 bytes
	// Outputs: the public key PublicKeyB that occupies 2048 bytes.
	//          the 256-bit shared secret SharedSecretB.
	// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
	uint32_t pk_A[OQS_RLWE_MSRLN16_PARAMETER_N], a[OQS_RLWE_MSRLN16_PARAMETER_N], v[OQS_RLWE_MSRLN16_PARAMETER_N], r[OQS_RLWE_MSRLN16_PARAMETER_N];
	int32_t sk_B[OQS_RLWE_MSRLN16_PARAMETER_N], e[OQS_RLWE_MSRLN16_PARAMETER_N];
	unsigned char seed[OQS_RLWE_MSRLN16_SEED_BYTES];
	CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

	oqs_rlwe_msrln16_decode_A(PublicKeyA, pk_A, seed);
	Status = oqs_rlwe_msrln16_generate_a(a, seed);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	Status = oqs_rlwe_msrln16_get_error(sk_B, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	Status = oqs_rlwe_msrln16_get_error(e, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	oqs_rlwe_msrln16_NTT_CT_std2rev_12289(sk_B, psi_rev_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_NTT_CT_std2rev_12289(e, psi_rev_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_smul(e, 3, OQS_RLWE_MSRLN16_PARAMETER_N);

	oqs_rlwe_msrln16_pmuladd((int32_t *)a, sk_B, e, (int32_t *)a, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_correction((int32_t *)a, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_N);

	Status = oqs_rlwe_msrln16_get_error(e, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	oqs_rlwe_msrln16_NTT_CT_std2rev_12289(e, psi_rev_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_smul(e, 81, OQS_RLWE_MSRLN16_PARAMETER_N);

	oqs_rlwe_msrln16_pmuladd((int32_t *)pk_A, sk_B, e, (int32_t *)v, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_INTT_GS_rev2std_12289((int32_t *)v, omegainv_rev_ntt1024_12289, omegainv10N_rev_ntt1024_12289, Ninv11_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_two_reduce12289((int32_t *)v, OQS_RLWE_MSRLN16_PARAMETER_N);
#if !defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_correction((int32_t *)v, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_N);
#endif

	Status = oqs_rlwe_msrln16_HelpRec(v, r, rand);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}
	oqs_rlwe_msrln16_Rec(v, r, SharedSecretB);
	oqs_rlwe_msrln16_encode_B(a, r, PublicKeyB);

cleanup:
	oqs_rlwe_msrln16_clear_words((void *)sk_B, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));
	oqs_rlwe_msrln16_clear_words((void *)e, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));
	oqs_rlwe_msrln16_clear_words((void *)a, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));
	oqs_rlwe_msrln16_clear_words((void *)v, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));
	oqs_rlwe_msrln16_clear_words((void *)r, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));

	return Status;
}


CRYPTO_STATUS oqs_rlwe_msrln16_SecretAgreement_A(unsigned char *PublicKeyB, int32_t *SecretKeyA, unsigned char *SharedSecretA) {
	// Alice's shared secret computation
	// It computes the shared secret SharedSecretA using Bob's public key PublicKeyB and Alice's private key SecretKeyA.
	// Inputs: Bob's public key PublicKeyB that consists of 2048 bytes
	//         the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
	// Output: the 256-bit shared secret SharedSecretA.
	uint32_t u[OQS_RLWE_MSRLN16_PARAMETER_N], r[OQS_RLWE_MSRLN16_PARAMETER_N];
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;

	oqs_rlwe_msrln16_decode_B(PublicKeyB, u, r);

	oqs_rlwe_msrln16_pmul(SecretKeyA, (int32_t *)u, (int32_t *)u, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_INTT_GS_rev2std_12289((int32_t *)u, omegainv_rev_ntt1024_12289, omegainv10N_rev_ntt1024_12289, Ninv11_ntt1024_12289, OQS_RLWE_MSRLN16_PARAMETER_N);
	oqs_rlwe_msrln16_two_reduce12289((int32_t *)u, OQS_RLWE_MSRLN16_PARAMETER_N);
#if !defined(RLWE_ASM_AVX2)
	oqs_rlwe_msrln16_correction((int32_t *)u, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_N);
#endif

	oqs_rlwe_msrln16_Rec(u, r, SharedSecretA);

// Cleanup
	oqs_rlwe_msrln16_clear_words((void *)u, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));
	oqs_rlwe_msrln16_clear_words((void *)r, OQS_RLWE_MSRLN16_NBYTES_TO_NWORDS(4 * OQS_RLWE_MSRLN16_PARAMETER_N));

	return Status;
}
