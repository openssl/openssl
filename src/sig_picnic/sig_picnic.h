/**
 * \file sig_picnic.h
 * \brief Header for the Microsoft Picnic library
 */

#ifndef __OQS_SIG_PICNIC_H
#define __OQS_SIG_PICNIC_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/sig.h>
#include <oqs/rand.h>

int OQS_SIG_picnic_get(OQS_SIG *sig, enum OQS_SIG_algid algid);
int OQS_SIG_picnic_keygen(const OQS_SIG *s, uint8_t *priv, uint8_t *pub);
int OQS_SIG_picnic_sign(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len);
int OQS_SIG_picnic_verify(const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len);
int OQS_SIG_picnic_shutdown(OQS_SIG *sig);
#endif
