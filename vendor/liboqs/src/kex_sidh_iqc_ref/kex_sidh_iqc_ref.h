
#ifndef KEX_SIDH_IQC_REF_H
#define KEX_SIDH_IQC_REF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

OQS_KEX *OQS_KEX_sidh_iqc_ref_new(OQS_RAND *rand, const char *named_parameters);

OQS_STATUS OQS_KEX_sidh_iqc_ref_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
OQS_STATUS OQS_KEX_sidh_iqc_ref_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
OQS_STATUS OQS_KEX_sidh_iqc_ref_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_sidh_iqc_ref_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_sidh_iqc_ref_free(OQS_KEX *k);

#ifdef __cplusplus
}
#endif

#endif /* KEX_SIDH_IQC_REF_H */
