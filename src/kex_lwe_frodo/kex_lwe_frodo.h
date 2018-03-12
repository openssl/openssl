/**
 * \file kex_lwe_frodo.h
 * \brief Header for LWE key exchange protocol Frodo.
 */

#ifndef __OQS_KEX_LWE_FRODO_H
#define __OQS_KEX_LWE_FRODO_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

OQS_KEX *OQS_KEX_lwe_frodo_new_recommended(OQS_RAND *rand, const uint8_t *seed, const size_t seed_len, const char *named_parameters);

OQS_STATUS OQS_KEX_lwe_frodo_alice_0_recommended(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
OQS_STATUS OQS_KEX_lwe_frodo_bob_recommended(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
OQS_STATUS OQS_KEX_lwe_frodo_alice_1_recommended(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_lwe_frodo_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_lwe_frodo_free(OQS_KEX *k);

#endif
