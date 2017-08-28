#include <assert.h>
#include <oqs/common.h>
#include <oqs/sig.h>
#ifdef ENABLE_PICNIC
#include <oqs/sig_picnic.h>
#endif

OQS_SIG *OQS_SIG_new(OQS_RAND *rand, enum OQS_SIG_algid algid) {
	if (rand == NULL) {
		return NULL;
	}

	OQS_SIG *s = malloc(sizeof(OQS_SIG));
	if (s == NULL) {
		return NULL;
	}
	s->rand = rand;

	switch (algid) {
#ifdef ENABLE_PICNIC
	case OQS_SIG_picnic_default:
	case OQS_SIG_picnic_42_14_FS:
	case OQS_SIG_picnic_42_14_UR:
	case OQS_SIG_picnic_1_316_FS:
	case OQS_SIG_picnic_1_316_UR:
	case OQS_SIG_picnic_10_38_FS:
	case OQS_SIG_picnic_10_38_UR:
		if (OQS_SIG_picnic_get(s, algid) != OQS_SUCCESS) {
			free(s);
			return NULL;
		}
		break;
#endif
	default:
		free(s);
		return NULL;
	}

	return s;
}

int OQS_SIG_keygen(const OQS_SIG *s, uint8_t *priv, uint8_t *pub) {
	if (s == NULL) {
		return OQS_ERROR;
	} else {
		return s->keygen(s, priv, pub);
	}
}

int OQS_SIG_sign(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len) {
	if (s == NULL) {
		return OQS_ERROR;
	} else {
		return s->sign(s, priv, msg, msg_len, sig, sig_len);
	}
}

int OQS_SIG_verify(const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len) {
	if (s == NULL) {
		return OQS_ERROR;
	} else {
		return s->verify(s, pub, msg, msg_len, sig, sig_len);
	}
}

void OQS_SIG_free(OQS_SIG *s) {
	if (s == NULL) {
		return;
	}
	s->shutdown(s);
	free(s);
}
