#include <oqs/sig.h>

#ifdef ENABLE_SIG_PICNIC

#include <string.h>
#include <oqs/common.h>
#include <oqs/rand.h>
#include "sig_picnic.h"
#include "external/picnic.h"

static char *Picnic_L1_FS_name = "Picnic_L1_FS";
static char *Picnic_L1_UR_name = "Picnic_L1_UR";
static char *Picnic_L3_FS_name = "Picnic_L3_FS";
static char *Picnic_L3_UR_name = "Picnic_L3_UR";
static char *Picnic_L5_FS_name = "Picnic_L5_FS";
static char *Picnic_L5_UR_name = "Picnic_L5_UR";
static size_t PRIV_KEY_LEN[] = {
    0,
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L1_FS),
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L1_UR),
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L3_FS),
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L3_UR),
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_FS),
    PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_UR)};
static size_t PUB_KEY_LEN[] = {
    0,
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L1_FS),
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L1_UR),
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L3_FS),
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L3_UR),
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_FS),
    PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_UR)};
static size_t SIG_LEN[] = {
    0,
    PICNIC_SIGNATURE_SIZE_Picnic_L1_FS,
    PICNIC_SIGNATURE_SIZE_Picnic_L1_UR,
    PICNIC_SIGNATURE_SIZE_Picnic_L3_FS,
    PICNIC_SIGNATURE_SIZE_Picnic_L3_UR,
    PICNIC_SIGNATURE_SIZE_Picnic_L5_FS,
    PICNIC_SIGNATURE_SIZE_Picnic_L5_UR};

typedef struct PICNIC_CTX {
	picnic_params_t params;
} PICNIC_CTX;

OQS_STATUS OQS_SIG_picnic_get(OQS_SIG *s, enum OQS_SIG_algid algid) {
	if (s == NULL) {
		return OQS_ERROR;
	}

	PICNIC_CTX *pctx = malloc(sizeof(PICNIC_CTX));
	if (pctx == NULL) {
		return OQS_ERROR;
	}

	// set the scheme-specific alg values
	// NOTE: the key and sig len values use macros, so we can't
	//       parametrized with pctx->params to shorten the code.
	switch (algid) {
	case OQS_SIG_picnic_default:
	case OQS_SIG_picnic_L1_FS:
		pctx->params = Picnic_L1_FS;
		s->method_name = Picnic_L1_FS_name;
		s->estimated_classical_security = 128;
		s->estimated_quantum_security = 64;
		break;
	case OQS_SIG_picnic_L1_UR:
		pctx->params = Picnic_L1_UR;
		s->method_name = Picnic_L1_UR_name;
		s->estimated_classical_security = 128;
		s->estimated_quantum_security = 64;
		break;
	case OQS_SIG_picnic_L3_FS:
		pctx->params = Picnic_L3_FS;
		s->method_name = Picnic_L3_FS_name;
		s->estimated_classical_security = 192;
		s->estimated_quantum_security = 96;
		break;
	case OQS_SIG_picnic_L3_UR:
		pctx->params = Picnic_L3_UR;
		s->method_name = Picnic_L3_UR_name;
		s->estimated_classical_security = 192;
		s->estimated_quantum_security = 96;
		break;
	case OQS_SIG_picnic_L5_FS:
		pctx->params = Picnic_L5_FS;
		s->method_name = Picnic_L5_FS_name;
		s->estimated_classical_security = 256;
		s->estimated_quantum_security = 128;
		break;
	case OQS_SIG_picnic_L5_UR:
		pctx->params = Picnic_L5_UR;
		s->method_name = Picnic_L5_UR_name;
		s->estimated_classical_security = 256;
		s->estimated_quantum_security = 128;
		break;
	default:
		return OQS_ERROR;
	}
	// set the ctx, sizes, and API functions
	s->ctx = pctx;
	s->priv_key_len = (uint16_t) PRIV_KEY_LEN[pctx->params];
	s->pub_key_len = (uint16_t) PUB_KEY_LEN[pctx->params];
	s->max_sig_len = (uint32_t) SIG_LEN[pctx->params];
	s->keygen = &OQS_SIG_picnic_keygen;
	s->sign = &OQS_SIG_picnic_sign;
	s->verify = &OQS_SIG_picnic_verify;
	s->free = &OQS_SIG_picnic_free;

	return OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_picnic_keygen(const OQS_SIG *s, uint8_t *priv, uint8_t *pub) {
	if (s == NULL || priv == NULL || pub == NULL) {
		return OQS_ERROR;
	}
	picnic_publickey_t pk;
	picnic_privatekey_t sk;
	picnic_params_t parameters = ((PICNIC_CTX *) s->ctx)->params;
	int ret = picnic_keygen(parameters, &pk, &sk, s->rand);
	if (ret != 0) { // DO NOT modify this return code to OQS_SUCCESS/OQS_ERROR
		return OQS_ERROR;
	}
	// serialize the public key
	int pk_len = picnic_write_public_key(&pk, pub, PUB_KEY_LEN[parameters]);
	if ((size_t) pk_len != PUB_KEY_LEN[parameters]) {
		return OQS_ERROR;
	}

	// serialize the private key
	int sk_len = picnic_write_private_key(&sk, priv, PRIV_KEY_LEN[parameters]);
	if ((size_t) sk_len != PRIV_KEY_LEN[parameters]) {
		return OQS_ERROR;
	}
	// wipe the private key
	OQS_MEM_cleanse(&sk, sizeof(picnic_privatekey_t));
	return OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_picnic_sign(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len) {
	if (s == NULL || priv == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
		return OQS_ERROR;
	}
	picnic_privatekey_t sk;
	picnic_params_t parameters = ((PICNIC_CTX *) s->ctx)->params;
	// deserialize the private key
	if (picnic_read_private_key(&sk, priv, PRIV_KEY_LEN[parameters]) != 0) {
		return OQS_ERROR;
	}
	if (picnic_sign(&sk, msg, msg_len, sig, sig_len) != 0) {
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_picnic_verify(UNUSED const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len) {
	if (pub == NULL || msg == NULL || sig == NULL) {
		return OQS_ERROR;
	}
	picnic_publickey_t pk;
	// deserialize the public key
	picnic_params_t parameters = ((PICNIC_CTX *) s->ctx)->params;
	if (picnic_read_public_key(&pk, pub, PUB_KEY_LEN[parameters]) != 0) {
		return OQS_ERROR;
	}
	if (picnic_verify(&pk, msg, msg_len, sig, sig_len) != 0) {
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

void OQS_SIG_picnic_free(OQS_SIG *s) {
	if (!s) {
		return;
	}
	free(s->ctx);
	s->ctx = NULL;
	free(s);
}

#endif
