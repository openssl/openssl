#if defined(_WIN32)
#pragma warning(disable : 4047 4090)
#endif

#if defined(_WIN32)
#define UNUSED
#else
#define UNUSED __attribute__((unused))
#endif

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#include <unistd.h>
#endif

#include <oqs/kex.h>
#include <oqs/rand.h>

#include "P503/P503_api.h"
#include "P751/P751_api.h"
#include "kex_sidh_msr.h"

#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

// a ctx object that holds the SIDH/SIKE key sizes and functions to call.
// then store it in k->ctx.
typedef struct SIDH_CTX {
	size_t priv_key_len;
	size_t pub_key_len;
	size_t shared_secret_len;
	size_t cipher_text_len;
	int is_sidh;
	// SIDH functions
	int (*EphemeralKeyGeneration_A)(const unsigned char *PrivateKeyA, unsigned char *PublicKeyA, OQS_RAND *rand);
	int (*EphemeralKeyGeneration_B)(const unsigned char *PrivateKeyB, unsigned char *PublicKeyB, OQS_RAND *rand);
	int (*EphemeralSecretAgreement_A)(const unsigned char *PrivateKeyA, const unsigned char *PublicKeyB, unsigned char *SharedSecretA);
	int (*EphemeralSecretAgreement_B)(const unsigned char *PrivateKeyB, const unsigned char *PublicKeyA, unsigned char *SharedSecretB);
	// SIKE functions
	int (*crypto_kem_keypair)(unsigned char *pk, unsigned char *sk, OQS_RAND *rand);
	int (*crypto_kem_enc)(unsigned char *ct, unsigned char *ss, const unsigned char *pk, OQS_RAND *rand);
	int (*crypto_kem_dec)(unsigned char *ss, const unsigned char *ct, const unsigned char *sk, OQS_RAND *rand);

} SIDH_CTX;

// NOTE: the SIDH lib returns 0 on success

OQS_KEX *OQS_KEX_sidh_msr_new(OQS_RAND *rand, const char *named_parameters) {
	if (named_parameters == NULL) {
		return NULL;
	}
	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}
	SIDH_CTX *sidh_ctx = malloc(sizeof(SIDH_CTX));
	if (sidh_ctx == NULL) {
		goto err;
	}
	if (strcmp(named_parameters, OQS_KEX_SIDH_503_params) == 0) {
		k->method_name = strdup("SIDH MSR p503");
		k->estimated_classical_security = 126; // same as AES128
		k->estimated_quantum_security = 84;    // same as AES128
		k->named_parameters = OQS_KEX_SIDH_503_params;
		sidh_ctx->is_sidh = 1;
		// from P503_api.h
		sidh_ctx->priv_key_len = 32;
		sidh_ctx->pub_key_len = 378;
		sidh_ctx->shared_secret_len = 126;
		sidh_ctx->EphemeralKeyGeneration_A = &EphemeralKeyGeneration_A_SIDHp503;
		sidh_ctx->EphemeralKeyGeneration_B = &EphemeralKeyGeneration_B_SIDHp503;
		sidh_ctx->EphemeralSecretAgreement_A = &EphemeralSecretAgreement_A_SIDHp503;
		sidh_ctx->EphemeralSecretAgreement_B = &EphemeralSecretAgreement_B_SIDHp503;
	} else if (strcmp(named_parameters, OQS_KEX_SIDH_751_params) == 0) {
		k->method_name = strdup("SIDH MSR p751");
		k->estimated_classical_security = 188; // same as AES192
		k->estimated_quantum_security = 125;   // same as AES192
		k->named_parameters = OQS_KEX_SIDH_751_params;
		sidh_ctx->is_sidh = 1;
		// from P751_api.h
		sidh_ctx->priv_key_len = 48;
		sidh_ctx->pub_key_len = 564;
		sidh_ctx->shared_secret_len = 188;
		sidh_ctx->EphemeralKeyGeneration_A = &EphemeralKeyGeneration_A_SIDHp751;
		sidh_ctx->EphemeralKeyGeneration_B = &EphemeralKeyGeneration_B_SIDHp751;
		sidh_ctx->EphemeralSecretAgreement_A = &EphemeralSecretAgreement_A_SIDHp751;
		sidh_ctx->EphemeralSecretAgreement_B = &EphemeralSecretAgreement_B_SIDHp751;
	} else if (strcmp(named_parameters, OQS_KEX_SIKE_503_params) == 0) {
		k->method_name = strdup("SIKE MSR p503");
		k->estimated_classical_security = 126; // same as AES128
		k->estimated_quantum_security = 84;    // same as AES128
		k->named_parameters = OQS_KEX_SIKE_503_params;
		sidh_ctx->is_sidh = 0;
		// from P503_api.h
		sidh_ctx->priv_key_len = 434;
		sidh_ctx->pub_key_len = 378;
		sidh_ctx->shared_secret_len = 16;
		sidh_ctx->cipher_text_len = 402;
		sidh_ctx->crypto_kem_keypair = &crypto_kem_keypair_SIKEp503;
		sidh_ctx->crypto_kem_enc = &crypto_kem_enc_SIKEp503;
		sidh_ctx->crypto_kem_dec = &crypto_kem_dec_SIKEp503;
	} else if (strcmp(named_parameters, OQS_KEX_SIKE_751_params) == 0) {
		k->method_name = strdup("SIKE MSR p751");
		k->estimated_classical_security = 188; // same as AES192
		k->estimated_quantum_security = 125;   // same as AES192
		k->named_parameters = OQS_KEX_SIKE_751_params;
		sidh_ctx->is_sidh = 0;
		// from P751_api.h
		sidh_ctx->priv_key_len = 644;
		sidh_ctx->pub_key_len = 564;
		sidh_ctx->shared_secret_len = 24;
		sidh_ctx->cipher_text_len = 596;
		sidh_ctx->crypto_kem_keypair = &crypto_kem_keypair_SIKEp751;
		sidh_ctx->crypto_kem_enc = &crypto_kem_enc_SIKEp751;
		sidh_ctx->crypto_kem_dec = &crypto_kem_dec_SIKEp751;
	} else {
		return NULL;
	}
	k->ctx = sidh_ctx;
	k->seed = NULL;
	k->seed_len = 0;
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_sidh_msr_alice_0;
	k->bob = &OQS_KEX_sidh_msr_bob;
	k->alice_1 = &OQS_KEX_sidh_msr_alice_1;
	k->alice_priv_free = &OQS_KEX_sidh_msr_alice_priv_free;
	k->free = &OQS_KEX_sidh_msr_free;

	goto cleanup;

err:
	free(k);
	k = NULL;
	free(sidh_ctx);

cleanup:
	return k;
}

OQS_STATUS OQS_KEX_sidh_msr_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {
	OQS_STATUS ret = OQS_ERROR;
	if (!k || !alice_priv || !alice_msg || !alice_msg_len) {
		return OQS_ERROR;
	}

	*alice_priv = NULL;
	*alice_msg = NULL;
	SIDH_CTX *sidh_ctx = (SIDH_CTX *) k->ctx;

	/* alice_msg is alice's public key */
	*alice_msg = calloc(sidh_ctx->pub_key_len, sizeof(uint8_t));
	if (*alice_msg == NULL) {
		goto err;
	}

	*alice_priv = calloc(sidh_ctx->priv_key_len, sizeof(uint8_t));
	if (*alice_priv == NULL) {
		goto err;
	}

	// generate Alice's key pair
	if (sidh_ctx->is_sidh) {
		if (sidh_ctx->EphemeralKeyGeneration_A((unsigned char *) *alice_priv, (unsigned char *) *alice_msg, k->rand)) {
			goto err;
		}
	} else {
		if (sidh_ctx->crypto_kem_keypair((unsigned char *) *alice_msg, (unsigned char *) *alice_priv, k->rand)) {
			goto err;
		}
	}
	*alice_msg_len = sidh_ctx->pub_key_len;

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

OQS_STATUS OQS_KEX_sidh_msr_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;
	uint8_t *bob_priv = NULL;

	if (!k || !alice_msg || !bob_msg || !bob_msg_len || !key || !key_len) {
		return OQS_ERROR;
	}

	*bob_msg = NULL;
	*key = NULL;
	SIDH_CTX *sidh_ctx = (SIDH_CTX *) k->ctx;

	if (alice_msg_len != sidh_ctx->pub_key_len) {
		goto err;
	}
	// bob's message is 1) for SIDH: bob's public key, and 2) for SIKE: bob's ciphertext
	*bob_msg_len = sidh_ctx->is_sidh ? sidh_ctx->pub_key_len : sidh_ctx->cipher_text_len;
	*bob_msg = calloc(*bob_msg_len, sizeof(uint8_t));
	if (*bob_msg == NULL) {
		goto err;
	}

	*key = calloc(sidh_ctx->shared_secret_len, sizeof(uint8_t));
	if (*key == NULL) {
		goto err;
	}

	// generate Bob's key pair and shared secret
	if (sidh_ctx->is_sidh) {
		bob_priv = calloc(sidh_ctx->priv_key_len, sizeof(uint8_t));
		if (bob_priv == NULL) {
			goto err;
		}

		// SIDH
		if (sidh_ctx->EphemeralKeyGeneration_B((unsigned char *) bob_priv, (unsigned char *) *bob_msg, k->rand)) {
			goto err;
		}

		if (sidh_ctx->EphemeralSecretAgreement_B((unsigned char *) bob_priv, (unsigned char *) alice_msg, (unsigned char *) *key)) {
			goto err;
		}
	} else {
		// SIKE
		if (sidh_ctx->crypto_kem_enc((unsigned char *) *bob_msg, (unsigned char *) *key, (unsigned char *) alice_msg, k->rand)) {
			goto err;
		}
	}
	*key_len = sidh_ctx->shared_secret_len;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*bob_msg);
	*bob_msg = NULL;
	free(*key);
	*key = NULL;

cleanup:
	free(bob_priv);

	return ret;
}

OQS_STATUS OQS_KEX_sidh_msr_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	if (!k || !alice_priv || !bob_msg || !key || !key_len) {
		return OQS_ERROR;
	}

	SIDH_CTX *sidh_ctx = (SIDH_CTX *) k->ctx;

	// bob's message is 1) for SIDH: bob's public key, and 2) for SIKE: bob's ciphertext
	if (bob_msg_len != (sidh_ctx->is_sidh ? sidh_ctx->pub_key_len : sidh_ctx->cipher_text_len)) {
		goto err;
	}

	*key = NULL;
	*key = calloc(sidh_ctx->shared_secret_len, sizeof(uint8_t));
	if (*key == NULL) {
		goto err;
	}
	*key_len = sidh_ctx->shared_secret_len;

	if (sidh_ctx->is_sidh) {
		// SIDH
		if (sidh_ctx->EphemeralSecretAgreement_A((unsigned char *) alice_priv, (unsigned char *) bob_msg, (unsigned char *) *key)) {
			goto err;
		}
	} else {
		// SIKE
		if (sidh_ctx->crypto_kem_dec((unsigned char *) *key, (unsigned char *) bob_msg, (unsigned char *) alice_priv, k->rand)) {
			goto err;
		}
	}

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*key);
	*key = NULL;

cleanup:

	return ret;
}

void OQS_KEX_sidh_msr_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_sidh_msr_free(OQS_KEX *k) {
	if (!k) {
		return;
	}
	free(k->ctx); // FIXMEOQS: do I need to cast to SIDH_CTX?
	k->ctx = NULL;
	free(k->method_name);
	k->method_name = NULL;
	free(k);
}
