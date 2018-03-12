/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_IMPL_H
#define PICNIC_IMPL_H

#include "mpc_lowmc.h"
#include "picnic.h"

#define MAX_DIGEST_SIZE 64
#define MAX_NUM_ROUNDS 438

typedef enum { TRANSFORM_FS, TRANSFORM_UR } transform_t;

typedef struct {
  lowmc_t lowmc;
  lowmc_implementation_f lowmc_impl;
  lowmc_verify_implementation_f lowmc_verify_impl;

  uint32_t security_level; /* bits */
  uint32_t digest_size;    /* bytes */
  uint32_t seed_size;      /* bytes */
  uint32_t num_rounds;

  uint32_t input_size;      /* bytes */
  uint32_t output_size;     /* bytes */
  uint32_t view_size;       /* bytes */
  uint32_t view_round_size; /* bits */

  uint32_t collapsed_challenge_size;       /* bytes */
  uint32_t unruh_without_input_bytes_size; /* bytes */
  uint32_t unruh_with_input_bytes_size;    /* bytes */
  uint32_t max_signature_size;             /* bytes */

  picnic_params_t params;
  transform_t transform;
} picnic_instance_t;

picnic_instance_t* oqs_sig_picnic_get_instance(picnic_params_t param);
const picnic_instance_t* picnic_instance_get(picnic_params_t param);

bool oqs_sig_picnic_fis_sign(const picnic_instance_t* pp, const uint8_t* plaintext, const uint8_t* private_key,
              const uint8_t* public_key, const uint8_t* msg, size_t msglen, uint8_t* sig,
              size_t* siglen);

bool oqs_sig_picnic_fis_verify(const picnic_instance_t* pp, const uint8_t* plaintext, const uint8_t* public_key,
                const uint8_t* msg, size_t msglen, const uint8_t* sig, size_t siglen);

void oqs_sig_picnic_visualize_signature(FILE* out, const picnic_instance_t* pp, const uint8_t* msg, size_t msglen,
                         const uint8_t* sig, size_t siglen);

PICNIC_EXPORT size_t PICNIC_CALLING_CONVENTION picnic_get_private_key_size(picnic_params_t param);
PICNIC_EXPORT size_t PICNIC_CALLING_CONVENTION picnic_get_public_key_size(picnic_params_t param);
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_sk_to_pk(const picnic_privatekey_t* sk,
                                                            picnic_publickey_t* pk);
void picnic_visualize(FILE* out, const uint8_t* public_key, size_t public_key_size,
                      const uint8_t* msg, size_t msglen, const uint8_t* sig, size_t siglen);

#endif
