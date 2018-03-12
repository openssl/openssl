/**
 * \file kex_sidh_msr.h
 * \brief Header for SIDH key exchange protocol from the Microsoft SIDH library
 */

#ifndef __OQS_KEX_SIDH_MSR_H
#define __OQS_KEX_SIDH_MSR_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

#define OQS_KEX_SIDH_503_params "sidh503"
#define OQS_KEX_SIDH_751_params "sidh751"
#define OQS_KEX_SIKE_503_params "sike503"
#define OQS_KEX_SIKE_751_params "sike751"

OQS_KEX *OQS_KEX_sidh_msr_new(OQS_RAND *rand, const char *named_parameters);

OQS_STATUS OQS_KEX_sidh_msr_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
OQS_STATUS OQS_KEX_sidh_msr_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
OQS_STATUS OQS_KEX_sidh_msr_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_sidh_msr_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_sidh_msr_free(OQS_KEX *k);

#endif
