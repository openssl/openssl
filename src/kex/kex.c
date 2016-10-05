#if defined(WINDOWS)
#define UNUSED
// FIXME: __attribute__ fails in VS, is there something else I should define?
#else
#define UNUSED __attribute__ ((unused))
#endif

#include <assert.h>

#include <oqs/kex.h>
#include <oqs/kex_rlwe_bcns15.h>

OQS_KEX *OQS_KEX_new(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, UNUSED const uint8_t *seed, UNUSED const UNUSED size_t seed_len, UNUSED const char *named_parameters) {
	switch (alg_name) {
	case OQS_KEX_alg_default:
	case OQS_KEX_alg_rlwe_bcns15:
		return OQS_KEX_rlwe_bcns15_new(rand);
	default:
		assert(0);
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
