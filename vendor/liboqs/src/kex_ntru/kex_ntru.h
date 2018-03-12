/**
 * \file kex_ntru.h
 * \brief Header for the NTRU implementation of OQS_KEX
 */

#ifndef __OQS_KEX_NTRU_H
#define __OQS_KEX_NTRU_H

#ifndef DISABLE_NTRU_ON_WINDOWS_BY_DEFAULT

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>
#include <oqs/kex.h>
#include <oqs/rand.h>

OQS_KEX *OQS_KEX_ntru_new(OQS_RAND *rand);

OQS_STATUS OQS_KEX_ntru_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
OQS_STATUS OQS_KEX_ntru_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
OQS_STATUS OQS_KEX_ntru_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_ntru_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_ntru_free(OQS_KEX *k);

#endif

#endif
