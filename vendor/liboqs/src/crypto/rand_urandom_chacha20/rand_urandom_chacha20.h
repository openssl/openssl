/**
 * \file rand_urandom_chacha20.h
 * \brief Header for the chacha implementation of OQS_RAND
 */

#ifndef __OQS_RAND_URANDOM_CHACHA20_H
#define __OQS_RAND_URANDOM_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/rand.h>

OQS_RAND *OQS_RAND_urandom_chacha20_new();

uint8_t OQS_RAND_urandom_chacha20_8(OQS_RAND *r);
uint32_t OQS_RAND_urandom_chacha20_32(OQS_RAND *r);
uint64_t OQS_RAND_urandom_chacha20_64(OQS_RAND *r);
void OQS_RAND_urandom_chacha20_n(OQS_RAND *r, uint8_t *out, size_t n);

void OQS_RAND_urandom_chacha20_free(OQS_RAND *r);

#endif
