#if defined(WINDOWS)
#define UNUSED
// FIXME: __attribute__ fails in VS, is there something else I should define?
#else
#define UNUSED __attribute__ ((unused))
#endif

#include <stdlib.h>
#include <string.h>
#if !defined(WINDOWS)
#include <unistd.h>
#include <strings.h>
#endif

#include <oqs/kex.h>
#include <oqs/rand.h>

#include "kex_rlwe_bcns15.h"
#include "local.h"

#include "rlwe_a.h"

OQS_KEX *OQS_KEX_rlwe_bcns15_new(OQS_RAND *rand) {

	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}

	k->ctx = malloc(sizeof(struct oqs_kex_rlwe_bcns15_fft_ctx));
	if (NULL == k->ctx) {
		return NULL;
	}

	k->method_name = strdup("RLWE BCNS15");
	k->estimated_classical_security = 163;
	k->estimated_quantum_security = 76;
	k->seed = NULL;
	k->seed_len = 0;
	k->named_parameters = NULL;
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_rlwe_bcns15_alice_0;
	k->bob = &OQS_KEX_rlwe_bcns15_bob;
	k->alice_1 = &OQS_KEX_rlwe_bcns15_alice_1;
	k->alice_priv_free = &OQS_KEX_rlwe_bcns15_alice_priv_free;
	k->free = &OQS_KEX_rlwe_bcns15_free;

	return k;

}

int OQS_KEX_rlwe_bcns15_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	int ret;

	*alice_priv = NULL;
	*alice_msg = NULL;

	/* allocate public/private key pair */
	*alice_msg = malloc(1024 * sizeof(uint32_t));
	if (*alice_msg == NULL) {
		goto err;
	}
	*alice_priv = malloc(1024 * sizeof(uint32_t));
	if (*alice_priv == NULL) {
		goto err;
	}

	/* generate public/private key pair */
	oqs_kex_rlwe_bcns15_generate_keypair(oqs_kex_rlwe_bcns15_a, (uint32_t *) *alice_priv, (uint32_t *) *alice_msg, k->ctx, k->rand);
	*alice_msg_len = 1024 * sizeof(uint32_t);

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*alice_msg);
	free(*alice_priv);

cleanup:
	return ret;

}

int OQS_KEX_rlwe_bcns15_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;

	uint8_t *bob_priv = NULL;
	*bob_msg = NULL;
	*key = NULL;

	if (alice_msg_len != 1024 * sizeof(uint32_t)) {
		goto err;
	}

	bob_priv = malloc(1024 * sizeof(uint32_t));
	if (bob_priv == NULL) {
		goto err;
	}
	/* allocate message and session key */
	*bob_msg = malloc(1024 * sizeof(uint32_t) + 16 * sizeof(uint64_t));
	if (*bob_msg == NULL) {
		goto err;
	}
	*key = malloc(16 * sizeof(uint64_t));
	if (*key == NULL) {
		goto err;
	}

	/* generate public/private key pair */
	oqs_kex_rlwe_bcns15_generate_keypair(oqs_kex_rlwe_bcns15_a, (uint32_t *) bob_priv, (uint32_t *) *bob_msg, k->ctx, k->rand);

	/* generate Bob's response */
	uint8_t *bob_rec = *bob_msg + 1024 * sizeof(uint32_t);
	oqs_kex_rlwe_bcns15_compute_key_bob((uint32_t *) alice_msg, (uint32_t *) bob_priv, (uint64_t *) bob_rec, (uint64_t *) *key, k->ctx, k->rand);
	*bob_msg_len = 1024 * sizeof(uint32_t) + 16 * sizeof(uint64_t);
	*key_len = 16 * sizeof(uint64_t);

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*bob_msg);
	free(*key);

cleanup:
	free(bob_priv);

	return ret;

}

int OQS_KEX_rlwe_bcns15_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;

	*key = NULL;

	if (bob_msg_len != 1024 * sizeof(uint32_t) + 16 * sizeof(uint64_t)) {
		goto err;
	}

	/* allocate session key */
	*key = malloc(16 * sizeof(uint64_t));
	if (*key == NULL) {
		goto err;
	}

	/* generate Alice's session key */
	const uint8_t *bob_rec = bob_msg + 1024 * sizeof(uint32_t);
	oqs_kex_rlwe_bcns15_compute_key_alice((uint32_t *)bob_msg, (uint32_t *)alice_priv, (uint64_t *) bob_rec, (uint64_t *) *key, k->ctx);
	*key_len = 16 * sizeof(uint64_t);

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*key);

cleanup:

	return ret;

}

void OQS_KEX_rlwe_bcns15_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_rlwe_bcns15_free(OQS_KEX *k) {
	if (!k) {
		return;
	}
	free(k->method_name);
	k->method_name = NULL;
	free(k->ctx);
	k->ctx = NULL;
	free(k);
}
