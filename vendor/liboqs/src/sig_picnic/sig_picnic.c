#if defined(WINDOWS)
#define UNUSED
#else
#define UNUSED __attribute__((unused))
#endif

#include <string.h>
#include <oqs/common.h>
#include <oqs/sig.h>
#include <oqs/rand.h>
#include "sig_picnic.h"
#include "picnic.h"

#define SERIALIZED_PUB_KEY_LEN (PICNIC_MAX_PUBLICKEY_SIZE + 1)
#define SERIALIZED_PRIV_KEY_LEN (PICNIC_MAX_PRIVATEKEY_SIZE + 1 + SERIALIZED_PUB_KEY_LEN)

static char *Picnic_42_14_FS = "Picnic_42_14_FS";
static char *Picnic_42_14_UR = "Picnic_42_14_UR";
static char *Picnic_1_316_FS = "Picnic_1_316_FS";
static char *Picnic_1_316_UR = "Picnic_1_316_UR";
static char *Picnic_10_38_FS = "Picnic_10_38_FS";
static char *Picnic_10_38_UR = "Picnic_10_38_UR";

// This flag indicates if OpenSSL is used by OQS (or an app including OQS, such
// as OpenSSL itself). If so, then Picnic skips the initialization and shutdown
// of OpenSSL, not to interfere with the containing app.
static int USES_OPENSSL =
#if USE_OPENSSL
    1;
#else
    0;
#endif

typedef struct PICNIC_CTX {
	picnic_params_t params;
} PICNIC_CTX;

int OQS_SIG_picnic_get(OQS_SIG *s, enum OQS_SIG_algid algid) {
	if (s == NULL) {
		return OQS_ERROR;
	}
	// init the alg
	picnic_params_t params;
	char *name;
	switch (algid) {
	case OQS_SIG_picnic_42_14_FS:
		params = LowMC_256_256_42_14_FS;
		name = Picnic_42_14_FS;
		break;
	case OQS_SIG_picnic_42_14_UR:
		params = LowMC_256_256_42_14_UR;
		name = Picnic_42_14_UR;
		break;
	case OQS_SIG_picnic_1_316_FS:
		params = LowMC_256_256_1_316_FS;
		name = Picnic_1_316_FS;
		break;
	case OQS_SIG_picnic_1_316_UR:
		params = LowMC_256_256_1_316_UR;
		name = Picnic_1_316_UR;
		break;
	case OQS_SIG_picnic_default:
	case OQS_SIG_picnic_10_38_FS:
		params = LowMC_256_256_10_38_FS;
		name = Picnic_10_38_FS;
		break;
	case OQS_SIG_picnic_10_38_UR:
		params = LowMC_256_256_10_38_UR;
		name = Picnic_10_38_UR;
		break;
	default:
		return OQS_ERROR;
	}
	PICNIC_CTX *pctx = malloc(sizeof(PICNIC_CTX));
	if (pctx == NULL) {
		return OQS_ERROR;
	}
	pctx->params = params;
	// read the path to the picnic params (if undefined, NULL is
	// returned and passed to picnic_init, and the default is used).
	const char *params_path = getenv("PICNIC_PARAMS_PATH");
	if (picnic_init(params, params_path, USES_OPENSSL) != 0) {
		free(pctx);
		return OQS_ERROR;
	}

	// set the scheme values
	s->method_name = name;
	s->estimated_classical_security = 256;
	s->estimated_quantum_security = 128;
	s->priv_key_len = SERIALIZED_PRIV_KEY_LEN;
	s->pub_key_len = SERIALIZED_PUB_KEY_LEN;
	s->max_sig_len = PICNIC_MAX_SIGNATURE_SIZE;
	s->keygen = &OQS_SIG_picnic_keygen;
	s->sign = &OQS_SIG_picnic_sign;
	s->verify = &OQS_SIG_picnic_verify;
	s->shutdown = &OQS_SIG_picnic_shutdown;
	s->ctx = pctx;
	return OQS_SUCCESS;
}

int OQS_SIG_picnic_keygen(const OQS_SIG *s, uint8_t *priv, uint8_t *pub) {
	if (s == NULL || priv == NULL || pub == NULL) {
		return OQS_ERROR;
	}
	picnic_publickey_t pk;
	picnic_privatekey_t sk;
	picnic_params_t parameters = ((PICNIC_CTX *) s->ctx)->params;
	int ret = picnic_keygen(parameters, &pk, &sk);
	if (ret != 0) {
		return OQS_ERROR;
	}
	// serialize the public key
	if (picnic_write_public_key(&pk, pub, SERIALIZED_PUB_KEY_LEN) != SERIALIZED_PUB_KEY_LEN) {
		return OQS_ERROR;
	}
	// serialize the private key
	// 1. prepend the public key
	memcpy(priv, pub, SERIALIZED_PUB_KEY_LEN);
	// 2. write the private key
	if (picnic_write_private_key(&sk, priv + SERIALIZED_PUB_KEY_LEN, SERIALIZED_PRIV_KEY_LEN) != (PICNIC_MAX_PRIVATEKEY_SIZE + 1)) {
		return OQS_ERROR;
	}
	// wipe the private key
	OQS_MEM_cleanse(&sk, sizeof(picnic_privatekey_t));
	return OQS_SUCCESS;
}

int OQS_SIG_picnic_sign(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len) {
	if (s == NULL || priv == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
		return OQS_ERROR;
	}
	picnic_privatekey_t sk;
	picnic_publickey_t pk;
	// deserialize the private key
	// 1. read the prepended public key
	if (picnic_read_public_key(&pk, priv, SERIALIZED_PUB_KEY_LEN) != 0) {
		return OQS_ERROR;
	}
	// 2. read the private key
	if (picnic_read_private_key(&sk, priv + SERIALIZED_PUB_KEY_LEN, SERIALIZED_PRIV_KEY_LEN, &pk) != 0) {
		return OQS_ERROR;
	}
	if (picnic_sign(&sk, msg, msg_len, sig, sig_len) != 0) {
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

int OQS_SIG_picnic_verify(UNUSED const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len) {
	if (pub == NULL || msg == NULL || sig == NULL) {
		return OQS_ERROR;
	}
	picnic_publickey_t pk;
	// deserialize the private key
	if (picnic_read_public_key(&pk, pub, SERIALIZED_PUB_KEY_LEN) != 0) {
		return OQS_ERROR;
	}
	if (picnic_verify(&pk, msg, msg_len, sig, sig_len) != 0) {
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

int OQS_SIG_picnic_shutdown(OQS_SIG *s) {
	if (s == NULL) {
		return OQS_ERROR;
	}
	picnic_shutdown(USES_OPENSSL);
	free(s->ctx);
	return OQS_SUCCESS;
}
