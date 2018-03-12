#include <assert.h>

#include <oqs/kex.h>

#include <oqs/kex_lwe_frodo.h>
#include <oqs/kex_ntru.h>
#include <oqs/kex_rlwe_bcns15.h>
#include <oqs/kex_rlwe_msrln16.h>
#include <oqs/kex_rlwe_newhope.h>
#include <oqs/kex_sidh_msr.h>

#ifdef ENABLE_CODE_MCBITS
#include <oqs/kex_code_mcbits.h>
#endif

#ifdef ENABLE_SIDH_IQC_REF
#include <oqs/kex_sidh_iqc_ref.h>
#endif
#ifdef ENABLE_KEX_RLWE_NEWHOPE_AVX2
#include <oqs/kex_rlwe_newhope_avx2.h>
#endif

#define UNUSED_KEX(expr) \
	do {                 \
		(void) (expr);   \
	} while (0)

OQS_KEX *OQS_KEX_new(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters) {

	//To disable warnings when the function arguments are not being used depending
	//on which algorithm has been disabled
	UNUSED_KEX(seed);
	UNUSED_KEX(seed_len);
	UNUSED_KEX(named_parameters);

	switch (alg_name) {
	case OQS_KEX_alg_default:
		return OQS_KEX_rlwe_bcns15_new(rand);
#ifdef ENABLE_KEX_LWE_FRODO
	case OQS_KEX_alg_lwe_frodo:
		return OQS_KEX_lwe_frodo_new_recommended(rand, seed, seed_len, named_parameters);
#else
		assert(0);
#endif
	case OQS_KEX_alg_code_mcbits:
#ifdef ENABLE_CODE_MCBITS
		return OQS_KEX_code_mcbits_new(rand);
#else
		assert(0);
#endif
#ifndef DISABLE_NTRU_ON_WINDOWS_BY_DEFAULT
#ifdef ENABLE_KEX_NTRU
	case OQS_KEX_alg_ntru:
		return OQS_KEX_ntru_new(rand);
#else
		assert(0);
#endif
#endif
	case OQS_KEX_alg_rlwe_bcns15:
		return OQS_KEX_rlwe_bcns15_new(rand);
#ifdef ENABLE_KEX_RLWE_MSRLN16
	case OQS_KEX_alg_rlwe_msrln16:
		return OQS_KEX_rlwe_msrln16_new(rand);
#else
		assert(0);
#endif
#ifdef ENABLE_KEX_RLWE_NEWHOPE
	case OQS_KEX_alg_rlwe_newhope:
		return OQS_KEX_rlwe_newhope_new(rand);
#else
		assert(0);
#endif
#ifdef ENABLE_KEX_RLWE_NEWHOPE_AVX2
	case OQS_KEX_alg_rlwe_newhope_avx2:
		return OQS_KEX_rlwe_newhope_avx2_new(rand);
#else
		assert(0);
#endif
#ifdef ENABLE_KEX_SIDH_MSR
	case OQS_KEX_alg_sidh_msr_503:
		return OQS_KEX_sidh_msr_new(rand, OQS_KEX_SIDH_503_params);
	case OQS_KEX_alg_sidh_msr_751:
		return OQS_KEX_sidh_msr_new(rand, OQS_KEX_SIDH_751_params);
	case OQS_KEX_alg_sike_msr_503:
		return OQS_KEX_sidh_msr_new(rand, OQS_KEX_SIKE_503_params);
	case OQS_KEX_alg_sike_msr_751:
		return OQS_KEX_sidh_msr_new(rand, OQS_KEX_SIKE_751_params);
#else
		assert(0);
#endif

	case OQS_KEX_alg_sidh_iqc_ref:
#ifdef ENABLE_SIDH_IQC_REF
		return OQS_KEX_sidh_iqc_ref_new(rand, named_parameters);
#else
		assert(0);
#endif
	default:
		assert(0);
		return NULL;
	}
}

OQS_STATUS OQS_KEX_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {
	if (k == NULL) {
		return OQS_ERROR;
	} else {
		return k->alice_0(k, alice_priv, alice_msg, alice_msg_len);
	}
}

OQS_STATUS OQS_KEX_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {
	if (k == NULL) {
		return OQS_ERROR;
	} else {
		return k->bob(k, alice_msg, alice_msg_len, bob_msg, bob_msg_len, key, key_len);
	}
}

OQS_STATUS OQS_KEX_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {
	if (k == NULL) {
		return OQS_ERROR;
	} else {
		return k->alice_1(k, alice_priv, bob_msg, bob_msg_len, key, key_len);
	}
}

void OQS_KEX_alice_priv_free(OQS_KEX *k, void *alice_priv) {
	if (k) {
		k->alice_priv_free(k, alice_priv);
	}
}

void OQS_KEX_free(OQS_KEX *k) {
	if (k) {
		k->free(k);
	}
}
