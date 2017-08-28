/**
 * \file sha3.h
 * \brief Header defining the API for OQS SHA3
 */

#ifndef __OQS_SHA3_H
#define __OQS_SHA3_H

#include <stdint.h>

#define OQS_SHA3_STATESIZE 25
#define OQS_SHA3_SHAKE128_RATE 168
#define OQS_SHA3_SHA3_256_RATE 136
#define OQS_SHA3_SHA3_512_RATE 72

void OQS_SHA3_keccak_squeezeblocks(unsigned char *h, unsigned long long int nblocks, uint64_t *s, unsigned int r);
void OQS_SHA3_sha3256(unsigned char *output, const unsigned char *input, unsigned int inputByteLen);
void OQS_SHA3_sha3512(unsigned char *output, const unsigned char *input, unsigned int inputByteLen);

// SHAKE128
void OQS_SHA3_shake128_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
void OQS_SHA3_shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void OQS_SHA3_shake128(unsigned char *output, unsigned long long outlen,
                       const unsigned char *input, unsigned long long inlen);

// cSHAKE128
void OQS_SHA3_cshake128_simple_absorb(uint64_t *s,
                                      uint16_t cstm, // 2-byte domain separator
                                      const unsigned char *in, unsigned long long inlen);
void OQS_SHA3_cshake128_simple_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void OQS_SHA3_cshake128_simple(unsigned char *output, unsigned long long outlen,
                               uint16_t cstm, // 2-byte domain separator
                               const unsigned char *in, unsigned long long inlen);

#endif
