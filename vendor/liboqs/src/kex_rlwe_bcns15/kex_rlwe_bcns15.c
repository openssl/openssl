#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#include <unistd.h>
#endif

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

#include "kex_rlwe_bcns15.h"
#include "local.h"

#include "rlwe_a.h"

#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

OQS_KEX *OQS_KEX_rlwe_bcns15_new(OQS_RAND *rand) {

	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}

	k->ctx = malloc(sizeof(struct oqs_kex_rlwe_bcns15_fft_ctx));
	if (k->ctx == NULL) {
		free(k);
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

OQS_STATUS OQS_KEX_rlwe_bcns15_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	OQS_STATUS ret;
	uint32_t *alice_msg_32 = NULL;

	*alice_priv = NULL;
	*alice_msg = NULL;

	/* allocate public/private key pair */
	alice_msg_32 = malloc(1024 * sizeof(uint32_t));
	if (alice_msg_32 == NULL) {
		goto err;
	}
	*alice_priv = malloc(1024 * sizeof(uint32_t));
	if (*alice_priv == NULL) {
		goto err;
	}

	/* generate public/private key pair */
	oqs_kex_rlwe_bcns15_generate_keypair(oqs_kex_rlwe_bcns15_a, (uint32_t *) *alice_priv, alice_msg_32, k->ctx, k->rand);
	*alice_msg = (uint8_t *) alice_msg_32;
	*alice_msg_len = 1024 * sizeof(uint32_t);

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(alice_msg_32);
	OQS_MEM_secure_free(*alice_priv, 1024 * sizeof(uint32_t));
	*alice_priv = NULL;

cleanup:
	return ret;
}

OQS_STATUS OQS_KEX_rlwe_bcns15_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	uint32_t *bob_priv = NULL;
	uint64_t *key_64 = NULL;

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
	key_64 = malloc(16 * sizeof(uint64_t));
	if (key_64 == NULL) {
		goto err;
	}

	/* generate public/private key pair */
	oqs_kex_rlwe_bcns15_generate_keypair(oqs_kex_rlwe_bcns15_a, bob_priv, (uint32_t *) *bob_msg, k->ctx, k->rand);

	/* generate Bob's response */
	uint8_t *bob_rec = *bob_msg + 1024 * sizeof(uint32_t);
	oqs_kex_rlwe_bcns15_compute_key_bob((uint32_t *) alice_msg, bob_priv, (uint64_t *) bob_rec, key_64, k->ctx, k->rand);
	*bob_msg_len = 1024 * sizeof(uint32_t) + 16 * sizeof(uint64_t);
	*key = (uint8_t *) key_64;
	*key_len = 16 * sizeof(uint64_t);

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*bob_msg);
	*bob_msg = NULL;
	OQS_MEM_secure_free(key_64, 16 * sizeof(uint64_t));

cleanup:
	OQS_MEM_secure_free(bob_priv, 1024 * sizeof(uint32_t));

	return ret;
}

OQS_STATUS OQS_KEX_rlwe_bcns15_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	uint64_t *key_64 = NULL;

	*key = NULL;

	if (bob_msg_len != 1024 * sizeof(uint32_t) + 16 * sizeof(uint64_t)) {
		goto err;
	}

	/* allocate session key */
	key_64 = malloc(16 * sizeof(uint64_t));
	if (key_64 == NULL) {
		goto err;
	}

	/* generate Alice's session key */
	const uint8_t *bob_rec = bob_msg + 1024 * sizeof(uint32_t);
	oqs_kex_rlwe_bcns15_compute_key_alice((uint32_t *) bob_msg, (uint32_t *) alice_priv, (uint64_t *) bob_rec, key_64, k->ctx);
	*key = (uint8_t *) key_64;
	*key_len = 16 * sizeof(uint64_t);

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	OQS_MEM_secure_free(key_64, 16 * sizeof(uint64_t));

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
