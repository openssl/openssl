#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#include <unistd.h>
#endif

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

#include "kex_rlwe_newhope.h"
#include "newhope.c"
#include "params.h"

#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

OQS_KEX *OQS_KEX_rlwe_newhope_new(OQS_RAND *rand) {
	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}
	k->method_name = strdup("RLWE NewHope");
	k->estimated_classical_security = 229; // http://eprint.iacr.org/2015/1092.pdf Table 1 NewHope dual known classical
	k->estimated_quantum_security = 206;   // http://eprint.iacr.org/2015/1092.pdf Table 1 NewHope dual known quantum
	k->seed = NULL;
	k->seed_len = 0;
	k->named_parameters = 0;
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_rlwe_newhope_alice_0;
	k->bob = &OQS_KEX_rlwe_newhope_bob;
	k->alice_1 = &OQS_KEX_rlwe_newhope_alice_1;
	k->alice_priv_free = &OQS_KEX_rlwe_newhope_alice_priv_free;
	k->free = &OQS_KEX_rlwe_newhope_free;
	return k;
}

OQS_STATUS OQS_KEX_rlwe_newhope_alice_0(UNUSED OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	OQS_STATUS ret;

	*alice_priv = NULL;
	*alice_msg = NULL;

	/* allocate public/private key pair */
	*alice_msg = malloc(NEWHOPE_SENDABYTES);
	if (*alice_msg == NULL) {
		goto err;
	}
	*alice_priv = malloc(sizeof(poly));
	if (*alice_priv == NULL) {
		goto err;
	}

	/* generate public/private key pair */
	keygen(*alice_msg, (poly *) (*alice_priv), k->rand);
	*alice_msg_len = NEWHOPE_SENDABYTES;

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

OQS_STATUS OQS_KEX_rlwe_newhope_bob(UNUSED OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	*bob_msg = NULL;
	*key = NULL;

	if (alice_msg_len != NEWHOPE_SENDABYTES) {
		goto err;
	}

	/* allocate message and session key */
	*bob_msg = malloc(NEWHOPE_SENDBBYTES);
	if (*bob_msg == NULL) {
		goto err;
	}
	*key = malloc(32);
	if (*key == NULL) {
		goto err;
	}

	/* generate Bob's response */
	sharedb(*key, *bob_msg, alice_msg, k->rand);
	*bob_msg_len = NEWHOPE_SENDBBYTES;
	*key_len = 32;

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

OQS_STATUS OQS_KEX_rlwe_newhope_alice_1(UNUSED OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	*key = NULL;

	if (bob_msg_len != NEWHOPE_SENDBBYTES) {
		goto err;
	}

	/* allocate session key */
	*key = malloc(32);
	if (*key == NULL) {
		goto err;
	}

	/* generate Alice's session key */
	shareda(*key, (poly *) alice_priv, bob_msg);
	*key_len = 32;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*key);
	*key = NULL;

cleanup:

	return ret;
}

void OQS_KEX_rlwe_newhope_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_rlwe_newhope_free(OQS_KEX *k) {
	if (k) {
		free(k->named_parameters);
		k->named_parameters = NULL;
		free(k->method_name);
		k->method_name = NULL;
	}
	free(k);
}
