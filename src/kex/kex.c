#include <assert.h>

#include <oqs/kex.h>
#include <oqs/kex_rlwe_bcns15.h>
#include <oqs/kex_rlwe_newhope.h>
#include <oqs/kex_rlwe_msrln16.h>
#include <oqs/kex_lwe_frodo.h>
#include <oqs/kex_sidh_cln16.h>

OQS_KEX *OQS_KEX_new(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters) {
	switch (alg_name) {
	case OQS_KEX_alg_default:
		return OQS_KEX_rlwe_bcns15_new(rand);
	case OQS_KEX_alg_rlwe_bcns15:
		return OQS_KEX_rlwe_bcns15_new(rand);
	case OQS_KEX_alg_rlwe_msrln16:
		return OQS_KEX_rlwe_msrln16_new(rand);
	case OQS_KEX_alg_rlwe_newhope:
		return OQS_KEX_rlwe_newhope_new(rand);
	case OQS_KEX_alg_lwe_frodo:
		return OQS_KEX_lwe_frodo_new_recommended(rand, seed, seed_len, named_parameters);
	case OQS_KEX_alg_sidh_cln16:
		return OQS_KEX_sidh_cln16_new(rand);
	default:
		assert(0);
		return NULL;
	}
}

int OQS_KEX_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {
	if (k == NULL) {
		return 0;
	} else {
		return k->alice_0(k, alice_priv, alice_msg, alice_msg_len);
	}
}

int OQS_KEX_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {
	if (k == NULL) {
		return 0;
	} else {
		return k->bob(k, alice_msg, alice_msg_len, bob_msg, bob_msg_len, key, key_len);
	}
}

int OQS_KEX_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {
	if (k == NULL) {
		return 0;
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
