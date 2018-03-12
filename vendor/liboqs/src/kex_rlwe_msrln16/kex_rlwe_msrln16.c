#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#include <unistd.h>
#endif

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

#include "LatticeCrypto.h"
#include "LatticeCrypto_priv.h"
#include "kex_rlwe_msrln16.h"

#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

OQS_KEX *OQS_KEX_rlwe_msrln16_new(OQS_RAND *rand) {

	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}

	k->ctx = NULL;
	k->method_name = strdup("RLWE MSR LN16");
	k->estimated_classical_security = 128;
	k->estimated_quantum_security = 128;
	k->seed = NULL;
	k->seed_len = 0;
	k->named_parameters = NULL;
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_rlwe_msrln16_alice_0;
	k->bob = &OQS_KEX_rlwe_msrln16_bob;
	k->alice_1 = &OQS_KEX_rlwe_msrln16_alice_1;
	k->alice_priv_free = &OQS_KEX_rlwe_msrln16_alice_priv_free;
	k->free = &OQS_KEX_rlwe_msrln16_free;

	return k;
}

OQS_STATUS OQS_KEX_rlwe_msrln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	OQS_STATUS ret;

	*alice_priv = NULL;
	/* alice_msg is alice's public key */
	*alice_msg = NULL;

	*alice_msg = malloc(OQS_RLWE_MSRLN16_PKA_BYTES);
	if (*alice_msg == NULL) {
		goto err;
	}
	*alice_priv = malloc(1024 * sizeof(uint32_t));
	if (*alice_priv == NULL) {
		goto err;
	}

	if (oqs_rlwe_msrln16_KeyGeneration_A((int32_t *) *alice_priv, (unsigned char *) *alice_msg, k->rand) != CRYPTO_SUCCESS) {
		goto err;
	}
	*alice_msg_len = OQS_RLWE_MSRLN16_PKA_BYTES;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*alice_msg);
	*alice_msg = NULL;
	free(*alice_priv);
	*alice_priv = NULL;

cleanup:
	return ret;
}

OQS_STATUS OQS_KEX_rlwe_msrln16_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	*bob_msg = NULL;
	*key = NULL;

	if (alice_msg_len != OQS_RLWE_MSRLN16_PKA_BYTES) {
		goto err;
	}
	*bob_msg = malloc(OQS_RLWE_MSRLN16_PKB_BYTES);
	if (*bob_msg == NULL) {
		goto err;
	}
	*key = malloc(OQS_RLWE_MSRLN16_SHAREDKEY_BYTES);
	if (*key == NULL) {
		goto err;
	}

	if (oqs_rlwe_msrln16_SecretAgreement_B((unsigned char *) alice_msg, (unsigned char *) *key, (unsigned char *) *bob_msg, k->rand) != CRYPTO_SUCCESS) {
		goto err;
	}

	*key_len = OQS_RLWE_MSRLN16_SHAREDKEY_BYTES;
	*bob_msg_len = OQS_RLWE_MSRLN16_PKB_BYTES;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*bob_msg);
	*bob_msg = NULL;
	free(*key);
	*key = NULL;

cleanup:

	return ret;
}

OQS_STATUS OQS_KEX_rlwe_msrln16_alice_1(UNUSED OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	*key = NULL;

	if (bob_msg_len != OQS_RLWE_MSRLN16_PKB_BYTES) {
		goto err;
	}

	*key = malloc(OQS_RLWE_MSRLN16_SHAREDKEY_BYTES);
	if (*key == NULL) {
		goto err;
	}

	if (oqs_rlwe_msrln16_SecretAgreement_A((unsigned char *) bob_msg, (int32_t *) alice_priv, (unsigned char *) *key) != CRYPTO_SUCCESS) {
		goto err;
	}

	*key_len = OQS_RLWE_MSRLN16_SHAREDKEY_BYTES;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*key);
	*key = NULL;

cleanup:

	return ret;
}

void OQS_KEX_rlwe_msrln16_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_rlwe_msrln16_free(OQS_KEX *k) {
	if (!k) {
		return;
	}
	free(k->method_name);
	k->method_name = NULL;
	free(k);
}
