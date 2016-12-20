/**
 * \file kex_sidh_cln16.h
 * \brief Header for SIDH key exchange protocol from the Microsoft SIDH library
 */

#ifndef __OQS_KEX_SIDH_CLN16_H
#define __OQS_KEX_SIDH_CLN16_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/kex.h>
#include <oqs/rand.h>

OQS_KEX *OQS_KEX_sidh_cln16_new(OQS_RAND *rand);

int OQS_KEX_sidh_cln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
int OQS_KEX_sidh_cln16_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
int OQS_KEX_sidh_cln16_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_sidh_cln16_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_sidh_cln16_free(OQS_KEX *k);

#endif
