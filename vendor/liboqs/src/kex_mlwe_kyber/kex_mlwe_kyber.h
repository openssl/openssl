/**
 * \file kex_mlwe_kyber.h
 * \brief Header for module-LWE key exchange protocol Kyber
 */

#ifndef __OQS_KEX_MLWE_KYBER_H
#define __OQS_KEX_MLWE_KYBER_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/kex.h>
#include <oqs/rand.h>

OQS_KEX *OQS_KEX_mlwe_kyber_new(OQS_RAND *rand);

int OQS_KEX_mlwe_kyber_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
int OQS_KEX_mlwe_kyber_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
int OQS_KEX_mlwe_kyber_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_mlwe_kyber_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_mlwe_kyber_free(OQS_KEX *k);

#endif
