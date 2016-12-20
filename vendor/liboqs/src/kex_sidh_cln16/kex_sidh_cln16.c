#if defined(WINDOWS)
#define UNUSED
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

#include "kex_sidh_cln16.h"
#include "SIDH.h"

OQS_KEX *OQS_KEX_sidh_cln16_new(OQS_RAND *rand) {

	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}

	// Curve isogeny system initialization
	PCurveIsogenyStruct curveIsogeny = oqs_sidh_cln16_curve_allocate(&CurveIsogeny_SIDHp751);
	if (curveIsogeny == NULL) {
		free(k);
		return NULL;
	}
	if (oqs_sidh_cln16_curve_initialize(curveIsogeny, rand, &CurveIsogeny_SIDHp751) != SIDH_CRYPTO_SUCCESS) {
		free(k);
		oqs_sidh_cln16_curve_free(curveIsogeny);
		return NULL;
	}
	k->ctx = curveIsogeny;
	k->method_name = strdup("SIDH CLN16");
	k->estimated_classical_security = 192;
	k->estimated_quantum_security = 128;
	k->seed = NULL;
	k->seed_len = 0;
	k->named_parameters = NULL; // TODO: create param p751 when we have more curves
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_sidh_cln16_alice_0;
	k->bob = &OQS_KEX_sidh_cln16_bob;
	k->alice_1 = &OQS_KEX_sidh_cln16_alice_1;
	k->alice_priv_free = &OQS_KEX_sidh_cln16_alice_priv_free;
	k->free = &OQS_KEX_sidh_cln16_free;

	return k;
}

int OQS_KEX_sidh_cln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	int ret;

	*alice_priv = NULL;
	/* alice_msg is alice's public key */
	*alice_msg = NULL;

	*alice_msg = malloc(SIDH_PUBKEY_LEN);
	if (*alice_msg == NULL) {
		goto err;
	}
	*alice_priv = malloc(SIDH_SECRETKEY_LEN);
	if (*alice_priv == NULL) {
		goto err;
	}

	if (oqs_sidh_cln16_KeyGeneration_A((unsigned char *) *alice_priv, (unsigned char *) *alice_msg, k->ctx, k->rand) != SIDH_CRYPTO_SUCCESS) {
		goto err;
	}
	*alice_msg_len = SIDH_PUBKEY_LEN;

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*alice_msg);
	free(*alice_priv);

cleanup:
	return ret;
}

int OQS_KEX_sidh_cln16_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;
	uint8_t *bob_priv = NULL;
	*bob_msg = NULL;
	*key = NULL;

	if (alice_msg_len != SIDH_PUBKEY_LEN) {
		goto err;
	}
	bob_priv = malloc(SIDH_SECRETKEY_LEN);
	if (bob_priv == NULL) {
		goto err;
	}
	*bob_msg = malloc(SIDH_PUBKEY_LEN);
	if (*bob_msg == NULL) {
		goto err;
	}
	*key = malloc(SIDH_SHAREDKEY_LEN);
	if (*key == NULL) {
		goto err;
	}

	if (oqs_sidh_cln16_KeyGeneration_B((unsigned char *) bob_priv, (unsigned char *) *bob_msg, k->ctx, k->rand) != SIDH_CRYPTO_SUCCESS) {
		goto err;
	}
	if (oqs_sidh_cln16_SecretAgreement_B((unsigned char *) bob_priv, (unsigned char *) alice_msg, (unsigned char *) *key, 0, k->ctx, k->rand) != SIDH_CRYPTO_SUCCESS) {
		goto err;
	}

	*key_len = SIDH_SHAREDKEY_LEN;
	*bob_msg_len = SIDH_PUBKEY_LEN;

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

int OQS_KEX_sidh_cln16_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;

	*key = NULL;

	if (bob_msg_len != SIDH_PUBKEY_LEN) {
		goto err;
	}

	*key = malloc(SIDH_SHAREDKEY_LEN);
	if (*key == NULL) {
		goto err;
	}

	if (oqs_sidh_cln16_SecretAgreement_A((unsigned char *) alice_priv, (unsigned char *) bob_msg, (unsigned char *) *key, false, k->ctx, k->rand) != SIDH_CRYPTO_SUCCESS) {
		goto err;
	}

	*key_len = SIDH_SHAREDKEY_LEN;

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*key);

cleanup:

	return ret;
}

void OQS_KEX_sidh_cln16_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_sidh_cln16_free(OQS_KEX *k) {
	if (!k) {
		return;
	}
	oqs_sidh_cln16_curve_free((PCurveIsogenyStruct) k->ctx);
	k->ctx = NULL;
	free(k->method_name);
	k->method_name = NULL;
	free(k);
}
