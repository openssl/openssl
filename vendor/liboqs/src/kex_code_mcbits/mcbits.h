/**
 * \file mcbits.h
 * \brief Header for internal functions of the code-based key exchange protocol McBits
 */

#ifndef __OQS_MCBITS_H
#define __OQS_MCBITS_H

#include "external/api.h"

int oqs_kex_mcbits_encrypt(
    unsigned char *c, size_t *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *pk,
    OQS_RAND *r);

int oqs_kex_mcbits_decrypt(
    unsigned char *m, size_t *mlen,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *sk);

int oqs_kex_mcbits_gen_keypair(
    unsigned char *pk,
    unsigned char *sk,
    OQS_RAND *r);

#endif
